rule malware_PhantomStealer {
    meta:
        description = "phantom stealer"
        author = "JPCERT/CC Incident Response Group"
        hash = "3e6c9cb5304d932483a0f0198a7c727d4898bcd4110b15cf2c7f7a731b2f195d"
        rule_usage = "memory scan"
        created_date = "2025-11-25"
        updated_date = "2025-11-25"

    strings:
        $s1 = "Phantom stealer" wide
        $s2 = "Phantom-DebugFile.log" wide
        $s3 = "Chrome_Phantom" wide

    condition:
        2 of them
}