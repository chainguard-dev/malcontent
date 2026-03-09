rule malware_SNOWLIGHT_loader {
    meta:
        description = "shellcode loader"
        author = "JPCERT/CC Incident Response Group"
        hash = "946f3935a4f69824e16bf815c3385cf6c1af4a5dd8df673861c286b8b65d7771"
        created_date = "2025-11-25"
        updated_date = "2025-11-25"
        reference = "https://sect.iij.ad.jp/blog/2025/11/unc5174-windows-snowlight-in-2025/"

    strings:
        $s1 = "Global\\MicrosoftEdgeUpdate" wide
        $s2 = {41 74 6C 54 68 75 6E 6B  5F 44 61 74 61 54 6F 43 00} // AtlThunk_DataToC
        $decode = {81 34 08 77 57 82 66 83 C0 04 3B C6 7C}

    condition:
        uint16(0) == 0x5A4D and
        2 of them
}

rule malware_SNOWLIGHT_ELF {
    meta:
        description = "SNOWLIGHT"
        author = "JPCERT/CC Incident Response Group"
        hash = "d4ce9744ab67f5c2298313a997b97e421de31f464e990d02dd4e55bf1fc5043d"
        created_date = "2025-11-25"
        updated_date = "2025-11-25"
        reference = "https://sect.iij.ad.jp/blog/2025/11/unc5174-windows-snowlight-in-2025/"

    strings:
        $s1 = "/tmp/log_de.log" ascii
        $s2 = "GET /?a=%s&h=%s&t=%s&p=%d HTTP/1.1" ascii
        $s3 = "[kworker/0:2]" ascii
        $decode = {80 30 99 48 FF C0 89 C6 29 EE 39 CE 7C}

    condition:
        uint32(0) == 0x464C457F and
        3 of them
}