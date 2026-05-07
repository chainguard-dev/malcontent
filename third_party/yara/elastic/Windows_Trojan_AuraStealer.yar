rule Windows_Trojan_AuraStealer_5dd9a496 {
    meta:
        author = "Elastic Security"
        id = "5dd9a496-f14f-4d96-a5e9-77432077374e"
        fingerprint = "a3213eaab576c626cbb0ba99c4486ba184df6bbe4b33eca66184257597157285"
        creation_date = "2026-04-09"
        last_modified = "2026-05-05"
        threat_name = "Windows.Trojan.AuraStealer"
        reference_sample = "b06c1fe3b5f6577b03053b7ada25dc592e6e2c62e6c5d6d14799be1f955ad5aa"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 8B 45 10 31 FF 85 C0 BE 06 00 00 00 0F 49 F0 83 7D 0C 00 0F 95 C0 89 F3 81 E3 00 04 00 00 0F 94 C2 20 C2 0F BA E6 10 0F B6 C2 8D 14 C5 00 00 00 00 }
        $b2 = { 8A 1C 82 88 1C 81 8A 5C 82 01 88 5C 81 01 8A 5C 82 02 88 5C 81 02 8A 5C 82 03 88 5C 81 03 40 83 F8 08 75 DC B8 08 00 00 00 8A 7C 81 FC }
    condition:
        all of them
}

