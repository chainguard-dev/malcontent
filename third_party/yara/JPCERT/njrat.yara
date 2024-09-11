rule malware_Njrat_strings {
          meta:
            description = "detect njRAT in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"
            hash1 = "d5f63213ce11798879520b0e9b0d1b68d55f7727758ec8c120e370699a41379d"

          strings:
            $reg = "SEE_MASK_NOZONECHECKS" wide fullword
            $msg = "Execute ERROR" wide fullword
            $ping = "cmd.exe /c ping 0 -n 2 & del" wide fullword
          condition:
            all of them
}
