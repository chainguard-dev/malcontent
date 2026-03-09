rule malware_SnakeKeylogger {
    meta:
        description = "Snake Keylogger (a.k.a. VIP Recovery)"
        author = "JPCERT/CC Incident Response Group"
        hash = "e7b49b01463ba069ef6b17e39fea65f06882a23bcbf821e52c5ef357cee141c5"
        rule_usage = "memory scan"
        created_date = "2025-11-25"
        updated_date = "2025-11-25"

    strings:
        $s1 = "VIP Recovery \\ --------" wide
        $s2 = "Keylogger_Recovered" wide

    condition:
        all of them
}