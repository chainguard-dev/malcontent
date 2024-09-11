rule malware_Emotet {
          meta:
            description = "detect Emotet in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $v4a = { BB 00 C3 4C 84 }
            $v4b = { B8 00 C3 CC 84 }
            $v5a = { 6D 4E C6 41 33 D2 81 C1 39 30 00 00 }
            $v6a = { C7 40 20 ?? ?? ?? 00 C7 40 10 ?? ?? ?? 00 C7 40 0C 00 00 00 00 83 3C CD ?? ?? ?? ?? 00 74 0E 41 89 48 ?? 83 3C CD ?? ?? ?? ?? 00 75 F2 }
            $v7a = { 6A 06 33 D2 ?? F7 ?? 8B DA 43 74 }
            $v7b = { 83 E6 0F 8B CF 83 C6 04 50 8B D6 E8 ?? ?? ?? ?? 59 6A 2F 8D 3C 77 58 66 89 07 83 C7 02 4B 75 }

          condition:
          all of ($v4*) or $v5a or $v6a or all of ($v7*)
}
