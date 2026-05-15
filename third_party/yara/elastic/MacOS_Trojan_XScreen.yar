rule MacOS_Trojan_XScreen_7837ad6c {
    meta:
        author = "Elastic Security"
        id = "7837ad6c-18b6-4b76-87fd-cb740215282c"
        fingerprint = "560f2bfc1a42425db853948113c0d11f63728cc495dbd0e7be0e7726653ec13a"
        creation_date = "2026-02-25"
        last_modified = "2026-04-06"
        threat_name = "MacOS.Trojan.XScreen"
        reference_sample = "432c720a9ada40785d77cd7e5798de8d43793f6da31c5e7b3b22ee0a451bb249"
        severity = 100
        arch_context = "x86, arm64"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "macos"
    strings:
        $a1 = { 2F 55 73 65 72 73 2F 53 68 61 72 65 64 2F 2E 5F 63 66 67 }
        $a2 = { 62 61 73 65 36 34 45 6E 63 6F 64 65 64 53 74 72 69 6E 67 57 69 74 68 4F 70 74 69 6F 6E 73 3A }
        $a3 = { 2F 70 72 69 76 61 74 65 2F 74 6D 70 2F 67 6F 6F 67 6C 65 5F 63 61 63 68 65 2E 64 62 }
        $a4 = { 5B 68 79 70 68 65 6E 5D }
        $a5 = { 67 65 6E 65 72 61 6C 50 61 73 74 65 62 6F 61 72 64 }
    condition:
        all of them
}

