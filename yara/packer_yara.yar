```yara
import "pe"
import "math"
import "hash"

rule Packed_UPX_Advanced
{
    meta:
        author = "illusion-sandbox"
        description = "Advanced UPX packer detection"
        date = "2026-06-10"
        confidence = "medium-high"

    strings:
        $upx0 = "UPX0" ascii nocase
        $upx1 = "UPX1" ascii nocase
        $upx2 = "UPX!" ascii
        $nrv2b = "NRV2B" ascii

        $stub1 = {
            60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57
        }

        $stub2 = {
            61 E9 ?? ?? ?? ??
        }

    condition:
        uint16(0) == 0x5A4D and

        (
            2 of ($upx*) or
            $nrv2b or
            any of ($stub*)
        ) and

        pe.number_of_sections <= 4 and

        for any i in (0 .. pe.number_of_sections - 1):
        (
            pe.sections[i].entropy > 7.0
        )
}

rule Suspicious_HighEntropy_PE
{
    meta:
        author = "illusion-sandbox"
        description = "PE with suspicious high entropy sections"

    condition:
        uint16(0) == 0x5A4D and

        for any i in (0 .. pe.number_of_sections - 1):
        (
            pe.sections[i].entropy > 7.2 and
            pe.sections[i].raw_data_size > 0x2000
        )
}

rule Suspicious_Packed_Malware
{
    meta:
        author = "illusion-sandbox"
        description = "Generic packed malware heuristic"

    condition:
        uint16(0) == 0x5A4D and

        filesize < 15MB and

        (
            for any i in (0 .. pe.number_of_sections - 1):
            (
                pe.sections[i].entropy > 7.3 and
                pe.sections[i].raw_data_size > 0x3000
            )
        ) and

        (
            pe.number_of_imports < 15 or
            pe.number_of_sections <= 3
        )
}

rule RWX_Section_Anomaly
{
    meta:
        author = "illusion-sandbox"
        description = "Detect RWX PE sections"

    condition:
        uint16(0) == 0x5A4D and

        for any i in (0 .. pe.number_of_sections - 1):
        (
            (
                pe.sections[i].characteristics & pe.SECTION_MEM_EXECUTE
            ) and
            (
                pe.sections[i].characteristics & pe.SECTION_MEM_WRITE
            )
        )
}

rule Large_Overlay_Suspicious
{
    meta:
        author = "illusion-sandbox"
        description = "Large PE overlay detection"

    condition:
        uint16(0) == 0x5A4D and
        pe.overlay.size > 50000
}

rule Delayed_Import_Abuse
{
    meta:
        author = "illusion-sandbox"
        description = "Suspicious delayed imports"

    condition:
        uint16(0) == 0x5A4D and
        pe.number_of_delayed_imports > 0
}

rule PowerShell_Loader_Indicators
{
    meta:
        author = "illusion-sandbox"
        description = "PowerShell loader indicators"

    strings:
        $ps1 = "powershell -enc" nocase ascii wide
        $ps2 = "FromBase64String" ascii wide
        $ps3 = "Invoke-Expression" ascii wide
        $ps4 = "IEX(" ascii wide
        $ps5 = "DownloadString" ascii wide
        $ps6 = "Net.WebClient" ascii wide
        $ps7 = "ExecutionPolicy Bypass" ascii wide

    condition:
        3 of them
}

rule Credential_Theft_Indicators
{
    meta:
        author = "illusion-sandbox"
        description = "Credential theft indicators"

    strings:
        $s1 = "lsass.exe" ascii wide
        $s2 = "MiniDumpWriteDump" ascii wide
        $s3 = "SeDebugPrivilege" ascii wide
        $s4 = "LogonPasswords" ascii wide
        $s5 = "sekurlsa" ascii wide
        $s6 = "WDigest" ascii wide
        $s7 = "kerberos" ascii wide

    condition:
        2 of them
}

rule Ransomware_Behavior_Indicators
{
    meta:
        author = "illusion-sandbox"
        description = "Ransomware operational indicators"

    strings:
        $r1 = "vssadmin delete shadows" nocase ascii wide
        $r2 = "wbadmin delete catalog" nocase ascii wide
        $r3 = "bcdedit /set" nocase ascii wide
        $r4 = "wevtutil cl" nocase ascii wide
        $r5 = ".locked" ascii wide
        $r6 = ".encrypted" ascii wide
        $r7 = "Your files have been encrypted" ascii wide
        $r8 = "bitcoin" nocase ascii wide
        $r9 = "tor browser" nocase ascii wide

    condition:
        3 of them
}

rule Suspicious_Process_Injection
{
    meta:
        author = "illusion-sandbox"
        description = "Process injection API indicators"

    strings:
        $api1 = "VirtualAllocEx" ascii wide
        $api2 = "WriteProcessMemory" ascii wide
        $api3 = "CreateRemoteThread" ascii wide
        $api4 = "NtWriteVirtualMemory" ascii wide
        $api5 = "QueueUserAPC" ascii wide
        $api6 = "SetThreadContext" ascii wide
        $api7 = "ResumeThread" ascii wide

    condition:
        3 of them
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

    condition:
        4 of them
}

rule Suspicious_Shellcode_Pattern
{
    meta:
        author = "illusion-sandbox"
        description = "Generic shellcode indicators"

    strings:
        $sc1 = {
            FC 48 83 E4 F0 E8
        }

        $sc2 = {
            31 C0 50 68
        }

        $sc3 = "kernel32.dll" ascii
        $sc4 = "LoadLibraryA" ascii
        $sc5 = "GetProcAddress" ascii

    condition:
        2 of them
}

rule Office_Macro_Dropper
{
    meta:
        author = "illusion-sandbox"
        description = "Office macro malware indicators"

    strings:
        $o1 = "AutoOpen" ascii wide
        $o2 = "Document_Open" ascii wide
        $o3 = "CreateObject" ascii wide
        $o4 = "WScript.Shell" ascii wide
        $o5 = "Shell.Application" ascii wide
        $o6 = "cmd.exe /c" ascii wide
        $o7 = "powershell.exe" ascii wide

    condition:
        3 of them
}

rule Generic_Malware_Heuristic
{
    meta:
        author = "illusion-sandbox"
        description = "Generic layered malware heuristic"

    strings:
        $a1 = "VirtualAlloc" ascii wide
        $a2 = "WriteProcessMemory" ascii wide
        $a3 = "cmd.exe" ascii wide
        $a4 = "powershell" ascii wide
        $a5 = "http://" ascii wide
        $a6 = "https://" ascii wide
        $a7 = "AppData" ascii wide
        $a8 = "Startup" ascii wide
        $a9 = "RunOnce" ascii wide

    condition:
        uint16(0) == 0x5A4D and

        filesize < 20MB and

        4 of them and

        (
            pe.number_of_imports < 30 or
            pe.overlay.size > 40000
        )
}
```
