rule Windows_Trojan_TCLBanker_a0287d4f {
    meta:
        author = "Elastic Security"
        id = "a0287d4f-b3c8-4299-a13e-592ba5192491"
        fingerprint = "6e07ed3db08c2e1da8003efab2730e97f7a9242717363f48fe1b1368821e45dd"
        creation_date = "2026-04-27"
        last_modified = "2026-05-05"
        threat_name = "Windows.Trojan.TCLBanker"
        reference_sample = "8a174aa70a4396547045aef6c69eb0259bae1706880f4375af71085eeb537059"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $str_decrypt = { 48 8D 41 1C 45 33 C0 48 8B C8 41 B9 FF 00 00 00 41 8D 50 23 }
        $str_decrypt2 = { 66 33 51 EC 66 89 11 48 8D 49 02 49 83 F8 0A }
        $syscall = { 75 1B 41 80 7F 01 8B 75 14 41 80 7F 02 D1 75 0D 41 80 7F 03 B8 75 06 }
        $etw_patch = { BA 03 00 00 00 66 C7 03 33 C0 48 8B CB C6 43 02 C3 }
        $gate = { 48 B8 F5 08 1D 97 3C E2 54 AB 48 89 44 24 48 48 B8 FD FE D9 45 25 B9 2E 95 }
        $lang_check = { BA FF 03 00 00 8B C8 66 23 C2 66 83 F8 16 75 }
        $watchdog = "WATCHDOG: thread count suspicious (baseline=%d, current=%d, delta=%d)" ascii fullword
    condition:
        3 of them
}

rule Windows_Trojan_TCLBanker_5df0f971 {
    meta:
        author = "Elastic Security"
        id = "5df0f971-0a77-43aa-a62f-8f10ff1be1e9"
        fingerprint = "2a857ea549a5129ff3cfc23ca2c26ce986b0c154a070638bb3d65946a8ec7542"
        creation_date = "2026-04-28"
        last_modified = "2026-05-05"
        threat_name = "Windows.Trojan.TCLBanker"
        reference_sample = "701d51b7be8b034c860bf97847bd59a87dca8481c4625328813746964995b626"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $s1 = "[Persistence] EnsureInstalled: exe=" wide fullword
        $s2 = "[Persistence] Task deleted OK" wide fullword
        $s3 = "CommandLine FROM Win32_Process WHERE Name = 'msedge.exe'" wide fullword
        $s4 = "KeyloggerHookThread" wide fullword
        $s5 = "Fique atento ao telefone informado" wide fullword
        $s6 = "O telefone deve ter 10" wide fullword
        $s7 = "Trabalhando em atualizacoes" wide fullword
        $s8 = "Win32_Process.Create falhou com codigo" wide fullword
    condition:
        4 of them
}

rule Windows_Trojan_TCLBanker_b5ef38c0 {
    meta:
        author = "Elastic Security"
        id = "b5ef38c0-fada-44e6-85ae-f7e7747f9996"
        fingerprint = "7af8112c19d301db1fa0a7605088b4b294a7b5ba20008c1f71bda46fc1babffd"
        creation_date = "2026-04-28"
        last_modified = "2026-05-05"
        threat_name = "Windows.Trojan.TCLBanker"
        reference_sample = "701d51b7be8b034c860bf97847bd59a87dca8481c4625328813746964995b626"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $s1 = "no_session: QR code detectado, sem conta logada" wide fullword
        $s2 = "error: campaign not configured" wide fullword
        $s3 = "error: 0 contacts after filter" wide fullword
        $s4 = "whatsapp: sessao carregada" wide fullword
        $s5 = "wpp_inject_failed" wide fullword
    condition:
        4 of them
}

rule Windows_Trojan_TCLBanker_8b41ae04 {
    meta:
        author = "Elastic Security"
        id = "8b41ae04-ef4d-4391-8c4e-0eaa95d7982d"
        fingerprint = "4dd69bcfbf7fd31d10bb5698f225ec0229168f15c76d609df30a9c35fdbd3f80"
        creation_date = "2026-04-28"
        last_modified = "2026-05-05"
        threat_name = "Windows.Trojan.TCLBanker"
        reference_sample = "668f932433a24bbae89d60b24eee4a24808fc741f62c5a3043bb7c9152342f40"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $s1 = "outlook: extraindo contatos" wide fullword
        $s2 = "error: 0 accounts with contacts in Outlook" wide fullword
        $s3 = "GetNamespace('MAPI')" wide fullword
        $s4 = "error: campaign not configured" wide fullword
        $s5 = "-eq 'caixa de entrada'" wide fullword
    condition:
        4 of them
}

