rule Microsoft_OneNote_with_Suspicious_String
{
    meta:
        author         = "InQuest Labs"
        description    = "This signature detects Microsoft OneNote files containing suspicious strings."
        created_date   = "2023-02-24"
        updated_date   = "2023-02-24"
        blog_reference = "https://inquest.net/blog/2023/02/27/youve-got-malware-rise-threat-actors-using-microsoft-onenote-malicious-campaigns"
        labs_reference = "N/A"
        labs_pivot     = "N/A"
        samples        = "660870c3f3e8ff105e5cc06b3b3d04436118fc67533c93d0df56bde359e335d0"

    strings:
        $suspicious_00 = "<script" nocase ascii wide
        $suspicious_01 = "cmd.exe" nocase ascii wide
        $suspicious_02 = "CreateObject" nocase ascii wide
        $suspicious_03 = "CreateProcess" nocase ascii wide
        $suspicious_04 = "echo off" nocase ascii wide
        $suspicious_05 = "ExecuteCmdAsync" nocase ascii wide
        $suspicious_06 = "mshta" nocase ascii wide
        $suspicious_07 = "msiexec" nocase ascii wide
        $suspicious_08 = "powershell" nocase ascii wide
        $suspicious_09 = "regsvr32" nocase ascii wide
        $suspicious_10 = "rundll32" nocase ascii wide
        $suspicious_11 = "schtasks" nocase ascii wide
        $suspicious_12 = "SetEnvironmentVariable" nocase ascii wide
        $suspicious_13 = "winmgmts" nocase ascii wide
        $suspicious_14 = "Wscript" nocase ascii wide
        $suspicious_15 = "WshShell" nocase ascii wide
    condition:
        uint32be(0) == 0xE4525C7B and any of ($suspicious*)
}
