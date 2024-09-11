rule malware_PlugX_config {
          meta:
            description = "detect PlugX in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $v1 = { 47 55 4c 50 00 00 00 00 }
            $v2a = { 68 40 25 00 00 }
            $v2c = { 68 58 2D 00 00 }
            $v2b = { 68 a0 02 00 00 }
            $v2d = { 68 a4 36 00 00 }
            $v2e = { 8D 46 10 68 }
            $v2f = { 68 24 0D 00 00 }
            $v2g = { 68 a0 02 00 00 }
            $v2h = { 68 e4 0a 00 00 }
            $enc1 = { C1 E? 03 C1 E? 07 2B ?? }
            $enc2 = { 32 5? ?? 81 E? ?? ?? 00 00 2A 5? ?? 89 ?? ?? 32 ?? 2A ?? 32 5? ?? 2A 5? ?? 32 }
            $enc3 = { B? 33 33 33 33 }
            $enc4 = { B? 44 44 44 44 }

          condition:
            $v1 at 0 or ($v2a and $v2b and $enc1) or ($v2c and $v2b and $enc1) or ($v2d and $v2b and $enc2) or ($v2d and $v2e and $enc2) or ($v2f and $v2g and $enc3 and $enc4) or ($v2h and $v2g and $enc3 and $enc4)
}
