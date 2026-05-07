rule Windows_Trojan_BrushWorm_7c2098ef {
    meta:
        author = "Elastic Security"
        id = "7c2098ef-a426-4331-8b04-e96fa8b42cb6"
        fingerprint = "931842bcd7cfa1afcaf5313a9f18097bc733ed52679ad9459d0e872319f85afd"
        creation_date = "2026-03-25"
        last_modified = "2026-05-05"
        threat_name = "Windows.Trojan.BrushWorm"
        reference_sample = "89891aa3867c1a57512d77e8e248d4a35dd32e99dcda0344a633be402df4a9a7"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = "internetCheckDomain" wide fullword
        $b = { B8 00 00 00 40 33 C9 0F A2 48 8D ?? ?? ?? 89 07 89 5F 04 89 4F 08 89 57 0C 45 33 C0 }
    condition:
        all of them
}

