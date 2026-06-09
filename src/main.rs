use clap::{Parser, Subcommand};
use std::env;
use std::process::exit;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::{thread, fs};

use illusion_sandbox::{run_in_sandbox, SandboxError};

#[derive(Parser)]
#[command(name = "illusion-sandbox")]
#[command(about = "Deterministic triage engine", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a single file
    Analyze {
        /// Path to the artifact to analyze
        target: PathBuf,
        /// Enable test mode (CI-friendly, skips firejail and dump operations)
        #[arg(long)]
        test_mode: bool,
        /// Optional output directory (unused by core runner; kept for future extension)
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Watch a directory and analyze new files as they appear
    Watch {
        /// Directory to watch
        dir: PathBuf,
        /// Poll interval in seconds
        #[arg(short, long, default_value_t = 5)]
        poll_secs: u64,
        /// Enable test mode
        #[arg(long)]
        test_mode: bool,
        /// Optional output directory
        #[arg(short, long)]
        out: Option<PathBuf>,
    },
    /// Hunt paths for suspicious files (one-shot)
    Hunt {
        /// Paths to scan
        paths: Vec<PathBuf>,
        /// Quarantine suspicious files
        #[arg(long)]
        quarantine: bool,
        /// Optional whitelist path (TOML)
        #[arg(long)]
        whitelist: Option<PathBuf>,
    },
}

fn find_latest_run_dir(base_name: &str, since_ts: u128) -> Option<PathBuf> {
    if let Ok(entries) = fs::read_dir("runs") {
        let mut best_ts = 0u128;
        let mut best_path: Option<PathBuf> = None;
        for e in entries.flatten() {
            let n = e.file_name().into_string().unwrap_or_default();
            if n.starts_with(base_name) {
                if let Some(idx) = n.rfind('-') {
                    let ts_str = &n[idx+1..];
                    if let Ok(ts) = ts_str.parse::<u128>() {
                        if ts >= since_ts && ts > best_ts {
                            best_ts = ts;
                            best_path = Some(e.path());
                        }
                    }
                }
            }
        }
        return best_path;
    }
    None
}

fn analyze(target: &PathBuf, _out: &Option<PathBuf>, test_mode: bool) -> Result<(), i32> {
    if test_mode { env::set_var("ILLUSION_TEST_MODE", "1"); } else { env::remove_var("ILLUSION_TEST_MODE"); }

    let base_name = target.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_else(|| "artifact".to_string());
    let start_ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis();

    match run_in_sandbox(target.to_str().unwrap()) {
        Ok(result) => {
            println!("--- Execution Report ---");
            println!("Exit code: {:?}", result.exit_code);
            println!("Timed out: {}", result.timed_out);
            println!("\n--- STDOUT ---\n{}", result.stdout);
            println!("\n--- STDERR ---\n{}", result.stderr);
            if let Some(run_dir) = find_latest_run_dir(&base_name, start_ts) {
                println!("Artifacts written to: {}", run_dir.display());
            }
            Ok(())
        }
        Err(e) => {
            match e {
                SandboxError::FirejailNotFound => {
                    eprintln!("Error: 'firejail' not found on PATH. Install with your package manager.");
                    Err(2)
                }
                SandboxError::Io(ioe) => {
                    eprintln!("I/O error while running sandbox: {}", ioe);
                    Err(3)
                }
                SandboxError::Utf8(u8e) => {
                    eprintln!("Encoding error reading child output: {}", u8e);
                    Err(4)
                }
            }
        }
    }
}

fn watch(dir: &PathBuf, poll_secs: u64, test_mode: bool, _out: &Option<PathBuf>) -> Result<(), i32> {
    if test_mode { env::set_var("ILLUSION_TEST_MODE", "1"); } else { env::remove_var("ILLUSION_TEST_MODE"); }
    fs::create_dir_all(dir).map_err(|_| 5)?;
    let processed = dir.join("processed");
    fs::create_dir_all(&processed).map_err(|_| 6)?;
    println!("Watching {} every {}s", dir.display(), poll_secs);
    loop {
        if let Ok(entries) = fs::read_dir(dir) {
            for e in entries.flatten() {
                let path = e.path();
                if path.is_file() {
                    // skip processed subdir
                    if let Some(name) = path.file_name().and_then(|s| s.to_str()) {
                        if name == "processed" { continue; }
                    }
                    println!("Processing {}", path.display());
                    let res = analyze(&path, _out, test_mode);
                    match res {
                        Ok(_) => {
                            // move to processed
                            let dest = processed.join(path.file_name().unwrap());
                            if let Err(_) = fs::rename(&path, &dest) {
                                let _ = fs::copy(&path, &dest);
                                let _ = fs::remove_file(&path);
                            }
                        }
                        Err(code) => {
                            eprintln!("Analysis failed for {}: code {}", path.display(), code);
                        }
                    }
                }
            }
        }
        thread::sleep(Duration::from_secs(poll_secs));
    }
}

fn main() {
    env_logger::init();
    let cli = Cli::parse();
    match &cli.command {
        Commands::Analyze { target, out, test_mode } => {
            if let Err(code) = analyze(target, out, *test_mode) { exit(code); }
        }
        Commands::Watch { dir, poll_secs, test_mode, out } => {
            if let Err(code) = watch(dir, *poll_secs, *test_mode, out) { exit(code); }
        }
        Commands::Hunt { paths, quarantine, whitelist } => {
            let paths_ref: Vec<PathBuf> = paths.iter().cloned().collect();
            match illusion_sandbox::hunt::hunt_paths(&paths_ref, *quarantine, whitelist.as_deref()) {
                Ok(findings) => {
                    println!("Hunt complete — {} findings", findings.len());
                    for f in findings.iter() {
                        println!("{} -> flags={:?} quarantined={:?}", f.path.display(), f.flags, f.quarantined);
                    }
                }
                Err(e) => {
                    eprintln!("Hunt failed: {}", e);
                    exit(7);
                }
            }
        }
    }
}
