rule Windows_Trojan_CastleLoader_173548b8 {
    meta:
        author = "Elastic Security"
        id = "173548b8-ff11-4528-8ef6-7e9f7d738e6c"
        fingerprint = "a894955aebf7db79279c58fa3800a21ec9c4cf44dcb6e516825824439931cc15"
        creation_date = "2025-08-14"
        last_modified = "2025-09-19"
        threat_name = "Windows.Trojan.CastleLoader"
        reference_sample = "1b6befc65b19a63b4131ce5bcc6e8c0552fe1e1d136ab94bc7d81b3924056156"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = { 8B 34 BA 33 DB 03 F1 BA AA AA AA AA 38 1E 74 ?? 0F BE 0C 1E 8B C2 F6 C3 01 75 ?? C1 E8 03 0F AF C1 8B CA C1 E1 07 33 C1 EB ?? C1 E8 05 33 C1 8B CA C1 E1 0B 03 C1 F7 D0 43 33 D0 }
        $b = { 8D 42 ?? 83 E0 03 0F B6 80 ?? ?? ?? ?? 66 33 44 0C ?? 66 89 84 0C ?? ?? ?? ?? 8D 42 ?? 83 E0 03 0F B6 80 ?? ?? ?? ?? 66 33 44 0C ?? 66 89 84 0C }
        $c = { 3D 20 6C 72 70 75 ?? 81 7D F8 65 70 79 68 75 ?? 81 7D F4 20 20 76 72 75 ?? B9 01 }
        $d = { 69 C0 6D 4E C6 41 05 39 30 00 00 }
        $e = { 83 7C 24 ?? 20 0F 85 ?? ?? ?? ?? 80 7C 24 ?? B8 0F 85 ?? ?? ?? ?? B9 01 00 00 00 C7 44 24 ?? B8 BB 00 00 C7 44 24 ?? C0 C2 10 00 C7 44 24 ?? 00 00 00 00 }
    condition:
        4 of them
}

