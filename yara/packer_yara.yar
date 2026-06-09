```yara
/*
    Cross-Platform Malware Hunting Ruleset
    Targets:
      - Windows PE
      - Linux ELF
      - Generic malware behaviors
      - Packers
      - Miners
      - Loaders
      - Reverse shells
      - Injection APIs
      - Ransomware traits
*/

import "pe"
import "elf"
import "math"
import "hash"

rule CrossPlatform_Packed_Executable
{
    meta:
        author = "illusion-sandbox"
        description = "Packed PE or ELF executable detection"
        severity = "high"

    condition:
        (
            uint16(0) == 0x5A4D and
            for any i in (0 .. pe.number_of_sections - 1):
            (
                pe.sections[i].entropy > 7.2 and
                pe.sections[i].raw_data_size > 0x3000
            )
        )
        or
        (
            elf.type == elf.ET_EXEC and
            for any i in (0 .. elf.number_of_sections - 1):
            (
                elf.sections[i].size > 0x3000 and
                math.entropy(
                    elf.sections[i].offset,
                    elf.sections[i].size
                ) > 7.2
            )
        )
}

rule UPX_Packer_Detection
{
    meta:
        author = "illusion-sandbox"
        description = "Detect UPX packed executables"

    strings:
        $upx1 = "UPX0" ascii nocase
        $upx2 = "UPX1" ascii nocase
        $upx3 = "UPX!" ascii
        $upx4 = "NRV2B" ascii

    condition:
        2 of them
}

rule Generic_ReverseShell_Indicators
{
    meta:
        author = "illusion-sandbox"
        description = "Reverse shell indicators"

    strings:
        $a1 = "/bin/sh" ascii
        $a2 = "/bin/bash" ascii
        $a3 = "bash -i" ascii
        $a4 = "nc -e" ascii
        $a5 = "socket.AF_INET" ascii
        $a6 = "subprocess.call" ascii
        $a7 = "powershell -enc" ascii wide
        $a8 = "cmd.exe /c" ascii wide
        $a9 = "CreateRemoteThread" ascii wide

    condition:
        2 of them
}

rule Generic_Process_Injection
{
    meta:
        author = "illusion-sandbox"
        description = "Process injection APIs"

    strings:
        $i1 = "VirtualAllocEx" ascii wide
        $i2 = "WriteProcessMemory" ascii wide
        $i3 = "CreateRemoteThread" ascii wide
        $i4 = "NtWriteVirtualMemory" ascii wide
        $i5 = "ptrace" ascii
        $i6 = "process_vm_writev" ascii
        $i7 = "mprotect" ascii
        $i8 = "dlopen" ascii

    condition:
        3 of them
}

rule CryptoMiner_Indicators
{
    meta:
        author = "illusion-sandbox"
        description = "Cryptocurrency miner indicators"

    strings:
        $m1 = "stratum+tcp://" ascii
        $m2 = "xmrig" ascii nocase
        $m3 = "minerd" ascii nocase
        $m4 = "cryptonight" ascii nocase
        $m5 = "donate-level" ascii
        $m6 = "ethash" ascii nocase
        $m7 = "cpuminer" ascii nocase

    condition:
        2 of them
}

rule Ransomware_Indicators
{
    meta:
        author = "illusion-sandbox"
        description = "Cross-platform ransomware indicators"

    strings:
        $r1 = "vssadmin delete shadows" nocase ascii wide
        $r2 = "wbadmin delete catalog" nocase ascii wide
        $r3 = "Your files have been encrypted" ascii wide
        $r4 = ".locked" ascii wide
        $r5 = ".encrypted" ascii wide
        $r6 = "bitcoin" nocase ascii wide
        $r7 = "tor browser" nocase ascii wide
        $r8 = "gpg --batch" ascii
        $r9 = "openssl enc" ascii

    condition:
        3 of them
}

rule Credential_Theft_Indicators
{
    meta:
        author = "illusion-sandbox"
        description = "Credential theft indicators"

    strings:
        $c1 = "lsass.exe" ascii wide
        $c2 = "MiniDumpWriteDump" ascii wide
        $c3 = "SeDebugPrivilege" ascii wide
        $c4 = "/etc/shadow" ascii
        $c5 = "/etc/passwd" ascii
        $c6 = "ssh-rsa" ascii
        $c7 = "id_rsa" ascii
        $c8 = "authorized_keys" ascii

    condition:
        2 of them
}

rule Suspicious_Network_Beaconing
{
    meta:
        author = "illusion-sandbox"
        description = "Beaconing and C2 indicators"

    strings:
        $n1 = "User-Agent:" ascii wide
        $n2 = "/gate.php" ascii wide
        $n3 = "/submit.php" ascii wide
        $n4 = "Mozilla/5.0" ascii wide
        $n5 = "POST /" ascii wide
        $n6 = "Content-Type:" ascii wide
        $n7 = "Keep-Alive" ascii wide
        $n8 = "curl -X POST" ascii
        $n9 = "wget http" ascii

    condition:
        4 of them
}

rule Generic_Suspicious_Script
{
    meta:
        author = "illusion-sandbox"
        description = "Suspicious script activity"

    strings:
        $s1 = "powershell -enc" ascii wide
        $s2 = "Invoke-Expression" ascii wide
        $s3 = "base64 -d" ascii
        $s4 = "chmod +x" ascii
        $s5 = "curl http" ascii
        $s6 = "wget http" ascii
        $s7 = "python -c" ascii
        $s8 = "perl -e" ascii
        $s9 = "nohup" ascii

    condition:
        3 of them
}

rule Generic_Backdoor_Behavior
{
    meta:
        author = "illusion-sandbox"
        description = "Backdoor and RAT indicators"

    strings:
        $b1 = "cmd.exe" ascii wide
        $b2 = "/bin/sh" ascii
        $b3 = "CreateProcess" ascii wide
        $b4 = "ShellExecute" ascii wide
        $b5 = "forkpty" ascii
        $b6 = "execve" ascii
        $b7 = "socket" ascii
        $b8 = "connect" ascii
        $b9 = "bind" ascii

    condition:
        4 of them
}

rule Generic_Malware_Heuristic
{
    meta:
        author = "illusion-sandbox"
        description = "Generic cross-platform malware heuristic"
        severity = "critical"

    strings:
        $g1  = "VirtualAlloc" ascii wide
        $g2  = "WriteProcessMemory" ascii wide
        $g3  = "CreateRemoteThread" ascii wide
        $g4  = "powershell" ascii wide
        $g5  = "cmd.exe" ascii wide
        $g6  = "/bin/bash" ascii
        $g7  = "/bin/sh" ascii
        $g8  = "curl http" ascii
        $g9  = "wget http" ascii
        $g10 = "stratum+tcp://" ascii
        $g11 = "lsass.exe" ascii wide
        $g12 = "/etc/shadow" ascii
        $g13 = "bitcoin" ascii wide
        $g14 = "User-Agent:" ascii wide
        $g15 = "socket.AF_INET" ascii

    condition:
        (
            uint16(0) == 0x5A4D or
            elf.type == elf.ET_EXEC
        )
        and
        filesize < 50MB
        and
        5 of them
}
```
