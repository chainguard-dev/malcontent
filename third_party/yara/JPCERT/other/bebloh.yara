rule malware_Bebloh_strings {
          meta:
            description = "detect Bebloh(a.k.a. URLZone) in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            reference = "internal research"

          strings:
            $crc32f = { b8 EE 56 0b ca }
            $dga = "qwertyuiopasdfghjklzxcvbnm123945678"
            $post1 = "&vcmd="
            $post2 = "?tver="

          condition:
            all of them
}
