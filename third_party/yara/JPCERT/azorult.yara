rule malware_Azorult {
          meta:
            description = "detect Azorult in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $v1 = "Mozilla/4.0 (compatible; MSIE 6.0b; Windows NT 5.1)"
            $v2 = "http://ip-api.com/json"
            $v3 = { c6 07 1e c6 47 01 15 c6 47 02 34 }

          condition:
            all of them
}
