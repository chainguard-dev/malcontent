rule Windows_Trojan_CristalLoaders_652f19ab {
    meta:
        author = "Elastic Security"
        id = "652f19ab-4c8c-48d0-a7a8-fdf592ea29f1"
        fingerprint = "f6f83fe8f20a1e9780e57c58b09786403663f6fd65f3d52d47e10bb98020d899"
        creation_date = "2026-03-18"
        last_modified = "2026-05-05"
        threat_name = "Windows.Trojan.CristalLoaders"
        reference_sample = "af92ec050ba5115a057c01365af3f154336921c1891a39a0186ac4ab7d45394f"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 51 52 41 50 41 51 41 52 41 53 48 83 EC 20 B9 5D 68 FA 3C BA }
        $a2 = { 51 52 41 50 41 51 41 52 41 53 48 83 EC 20 B9 5B BC 4A 6A BA }
        $a3 = { 41 51 52 41 52 41 50 41 53 48 83 EC 20 B9 5B BC 4A 6A BA }
        $b1 = { 51 52 41 50 41 51 41 52 41 53 48 83 EC 20 }
        $b2 = { 41 5B 41 5A 41 59 41 58 5A 59 FF D0 }
    condition:
        1 of ($a*) or all of ($b*)
}

