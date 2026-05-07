rule Windows_Trojan_BrushLogger_304ee146 {
    meta:
        author = "Elastic Security"
        id = "304ee146-8abf-4d4d-8b50-df90a641f400"
        fingerprint = "bd66e7980779c7065a544d3578a685007fb00d6990320001ef8869a1d0ad969e"
        creation_date = "2026-03-25"
        last_modified = "2026-05-05"
        threat_name = "Windows.Trojan.BrushLogger"
        reference_sample = "4f1ea5ed6035e7c951e688bd9c2ec47a1e184a81e9ae783d4a0979501a1985cf"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = "%02d-%02d-%d %02d:%02d " fullword
        $b = { 81 ?? ?? A1 00 00 00 74 09 81 ?? ?? A0 00 00 00 75 09 6A 00 6A 10 E8 }
    condition:
        all of them
}

