rule malware_STONEMITE {
    meta:
        description = "STONEMITE RAT"
        author = "JPCERT/CC Incident Response Group"
        hash = "da1b52f8f3d2f99abf17790a2eb932f7db3c70bb71af89a5eff2e59540c9f78c"
        created_date = "2025-11-14"
        updated_date = "2025-11-14"

    strings:
        $s1 = {3D 27 07 00 00 75 ?? 6A 00 6A 00 68 28 07 00 00 FF 75 ?? E8}
        $s2 = "POST /%s HTTP/1.1" ascii
        $s3 = "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.90 Safari/537.36" ascii

    condition:
        all of them
}