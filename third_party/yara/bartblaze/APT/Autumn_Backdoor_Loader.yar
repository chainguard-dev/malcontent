rule Autumn_Backdoor_Loader
{
    meta:
        id = "5ARAyUbFnFrLABeyLz9bWm"
        fingerprint = "v1_sha256_09a399531a2e2f8064b1c9862949fa1c9eca1ddab19bfb62a5ce947e002445cc"
        version = "1.0"
        date = "2025-11-18"
        modified = "2025-11-20"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies backdoor loader (stage 2), used by a China-nexus APT, as seen in the Autumn Dragon report."
        category = "MALWARE"
        malware = "UNKNOWN"
        malware_type = "BACKDOOR"
        reference = "https://cyberarmor.tech/blog/autumn-dragon-china-nexus-apt-group-targets-south-east-asia"
        hash = "843fca1cf30c74edd96e7320576db5a39ebf8d0a708bde8ccfb7c12e45a7938c"
        hash = "d7711333c34a27aed5d38755f30d14591c147680e2b05eaa0484c958ddaae3b6"

    strings:
        $pdb_dev = "\\Dev\\ApplicationDllHijacking\\"
        $pdb_user = "\\Users\\LG02\\Desktop\\???\\"
    
    condition:
        any of them
}
