rule malware_VeletrixLoader {
    meta:
        description = "Veletrix Loader"
        author = "JPCERT/CC Incident Response Group"
        hash = "253ff072d71caeb02ed596fd6aa266e625f51a09d49d82726a11b66218bdd6c3"
        created_date = "2025-10-16"
        updated_date = "2025-10-16"

    strings:
        $logfile = {
            C7 45 ?? 6C 6F 67 5F
            48 8D 4D ??
            C7 45 ?? 64 65 2E 00
            C7 85 ?? ?? ?? ?? 6C 6F 67 00
        }

        $xor_decode = {
            41 8D 0C 30
            45 03 C6
            80 34 39 99
            44 3B C0
        }

    condition:
        all of them
}

rule malware_VeletrixLoader_python {
    meta:
        description = "Veletrix Loader"
        author = "JPCERT/CC Incident Response Group"
        hash = "96fe34f367423a1ca75e0e0b293ef4918ca30f5efcb36c9b67dec746493f3b37"
        created_date = "2025-10-16"
        updated_date = "2025-10-16"

    strings:
        $msg = "执行Shellcode（生产环境需极度谨慎！）" ascii
        $func = "def run_shellcode(shellcode)" ascii
        $shell = "\\x64\\x65\\x2e\\x00\\xc7" ascii

    condition:
        2 of them
}