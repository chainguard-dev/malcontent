rule Oyster
{
    meta:
        id = "7kE7GnnyOPX7qw3Kwwua0X"
        fingerprint = "v1_sha256_c635149f6091ca338956c8c7639aeeab30d70456e06e5d894a1bef0a1c0a031a"
        version = "1.0"
        date = "2025-09-26"
        modified = "2025-09-26"
        status = "RELEASED"
        sharing = "TLP:WHITE"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies Oyster aka Broomstick aka CleanUp backdoor."
        category = "MALWARE"
        malware = "OYSTER"
        malware_type = "BACKDOOR"
        reference = "https://x.com/roo7cause/status/1971453273862176887"
        reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.broomstick"
        hash = "169157f51c05aafda68eb367219a826ecdc90e941e4397da20021b0f4ee2ae14"

    strings:
        $ = "WordPressAgent" fullword
        $ = "FingerPrint" fullword
        $ = "TimeSleep: %d"
        $ = "[CountStartupProcessSystem] EnumProcesses failed"
        $ = "Fail Find End .ICO File"
        $ = "Fail Find DLL File Round 2"
        $ = "Mutex already exists, another instance is running."
        $ = "cmd.exe /C ping 1.1.1.1 -n 1 -w 3000 > Nul & Del /f /q"
        $ = "The installation has not been completed successfully. We kindly ask you to try again later."

    condition:
        6 of them
}
