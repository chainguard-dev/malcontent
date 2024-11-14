rule malware_Remcos_strings {
          meta:
            description = "detect Remcos in memory"
            author = "JPCERT/CC Incident Response Group"
            rule_usage = "memory scan"


          strings:
            $remcos = "Remcos" ascii fullword
            $url1 = "Breaking-Security.Net" ascii fullword
            $url2 = "BreakingSecurity.Net" ascii fullword
            $resource = "SETTINGS" ascii wide fullword

          condition:
            1 of ($url*) and $remcos and $resource
}
