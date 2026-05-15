rule Windows_Trojan_VoidStealer_b17abbfd {
    meta:
        author = "Elastic Security"
        id = "b17abbfd-8e5f-403e-b7fd-1bf6d3941f19"
        fingerprint = "30095f55311c8b621c828ccc621e8877ca963e9f2760636e45609900ccbfa5f3"
        creation_date = "2026-03-27"
        last_modified = "2026-05-05"
        threat_name = "Windows.Trojan.VoidStealer"
        reference_sample = "f783fde5cf7930e4b3054393efadd3675b505cbef8e9d7ae58aa35b435adeea4"
        severity = 100
        arch_context = "x86"
        scan_context = "file, memory"
        license = "Elastic License v2"
        os = "windows"
    strings:
        $a1 = { 7B 22 62 75 69 6C 64 5F 69 64 22 3A 22 }
        $a2 = "\\\\.\\pipe\\browser_key_pipe" ascii wide
        $a3 = { 22 2C 22 73 65 73 73 69 6F 6E 5F 69 64 22 3A 22 }
        $a4 = "%d %b %y %H:%M %Z" wide fullword
        $a5 = "OSCrypt.AppBoundProvider.Decrypt.ResultCode" ascii fullword
        $a6 = "ft5HAfKQvejy8notJdgHNtzEZuHqShVuf2SUNW6wQ1r5dmM17r/rbmrT9AHdBQ==" ascii fullword
    condition:
        5 of them
}

