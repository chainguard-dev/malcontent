rule GrimResource
{
    meta:
        id = "6AllkuLIfG9lO9ZRaxm6Ni"
        fingerprint = "v1_sha256_9d266207dd5688a68a837d9d764aa7390183a8b551b0524e6d21f80a34afeb29"
        version = "1.0"
        date = "2025-12-15"
        modified = "2025-12-15"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "BARTBLAZE"
        author = "@bartblaze"
        description = "Identifies GrimResource and potential derivatives or variants."
        category = "INFO"
        reference = "https://www.elastic.co/security-labs/grimresource"

    strings:
        $xml = "<?xml"

        $grim_a = "MMC_ConsoleFile"
        $grim_b = ".loadXML("

        $other_a = "ActiveXObject"
        $other_b = "ms:script"
        $other_c = "CDATA"

    condition:
        $xml at 0 and (all of ($grim_*) or all of ($other_*))
}
