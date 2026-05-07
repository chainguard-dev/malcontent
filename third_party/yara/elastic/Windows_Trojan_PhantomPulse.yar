rule Windows_Trojan_PhantomPulse_eaaa34fb {
    meta:
        author = "Elastic Security"
        id = "eaaa34fb-eb17-433a-ba0c-f5245cb581b4"
        fingerprint = "36f5a16a014b315dc04c4c8f59bc3b653b17d0f67b5723a6b662b58709845008"
        creation_date = "2026-04-13"
        last_modified = "2026-05-05"
        threat_name = "Windows.Trojan.PhantomPulse"
        reference_sample = "9e3890d43366faec26523edaf91712640056ea2481cdefe2f5dfa6b2b642085d"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a = "[UNINSTALL 2/6] Removing Scheduled Task..." fullword
        $b = "PhantomInject: host PID=%lu" fullword
        $c = "inject: shellcode detected -> InjectShellcodePhantom" fullword
        $d = "inject: shellcode detected, using phantom section hijack" fullword
    condition:
        all of them
}

