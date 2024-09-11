rule malware_SmokeLoader {
          meta:
            description = "detect SmokeLoader in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "https://www.cert.pl/en/news/single/dissecting-smoke-loader/"

          strings:
            $a1 = { B8 25 30 38 58 }
            $b1 = { 81 3D ?? ?? ?? ?? 25 00 41 00 }
            $c1 = { C7 ?? ?? ?? 25 73 25 73 }

          condition:
            $a1 and $b1 and $c1
}
