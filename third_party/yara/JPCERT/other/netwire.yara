rule malware_netwire_strings {
           meta:
            description = "detect netwire in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $v1 = "HostId-%Rand%"
            $v2 = "mozsqlite3"
            $v3 = "[Scroll Lock]"
            $v4 = "GetRawInputData"
            $ping = "ping 192.0.2.2"
            $log = "[Log Started] - [%.2d/%.2d/%d %.2d:%.2d:%.2d]"

          condition:
            ($v1) or ($v2 and $v3 and $v4) or ($ping and $log)
}
