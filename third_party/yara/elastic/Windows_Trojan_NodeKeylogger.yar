rule Windows_Trojan_NodeKeylogger_ffc7db41 {
    meta:
        author = "Elastic Security"
        id = "ffc7db41-c3a2-4fb7-98db-d8d93a607ef4"
        fingerprint = "cbaa7c21cbf33754b22b820554e7f0a355f6ea76e4799dd47ff905a0ba851b01"
        creation_date = "2026-03-22"
        last_modified = "2026-05-05"
        threat_name = "Windows.Trojan.NodeKeylogger"
        reference_sample = "e58864cc22cd8ec17ae35dd810455d604aadab7c3f145b6c53b3c261855a4bb1"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a0 = "%s,%s,%i,%i,%ld,%ld,%i" fullword
        $a1 = "MOUSE" fullword
        $a2 = "KEYBOARD" fullword
        $a3 = "DOWN" fullword
        $b0 = { 81 7D 08 08 02 00 00 [6] 81 7D 08 01 02 00 00 73 ?? 81 7D 08 05 01 00 00 74 ?? 81 7D 08 05 01 00 00 [6] 81 7D 08 04 01 00 00 }
    condition:
        all of them
}

