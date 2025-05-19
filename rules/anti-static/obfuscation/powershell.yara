rule powershell_byte_xor: critical windows {
  meta:
    description = "powershell byte XOR"
    filetypes   = "ps1"

  strings:
    $ps_powershell = "powershell"
    $ps_bytes      = "[System.IO.File]"
    $xor           = "-bxor" fullword
    $not_docs      = " https://docs.microsoft.com"
    $not_verbs     = "-cnotcontains"
    $not_elastic   = "\"Suspicious Windows Powershell Arguments\""

  condition:
    filesize < 16KB and $xor and any of ($ps*) and none of ($not*)
}

rule powershell_compact: medium windows {
  meta:
    description = "unusually compact PowerShell representation"
    author      = "Florian Roth"
    filetypes   = "ps1"

  strings:
    $InokeExpression = ");iex" ascii wide nocase

  condition:
    filesize < 16777216 and any of them
}

rule powershell_encoded: high windows {
  meta:
    description = "Encoded Powershell"
    author      = "Florian Roth"
    filetypes   = "ps1"

  strings:
    $ref = / -[eE][decoman]{0,41} ['"]?(JAB|SUVYI|aWV4I|SQBFAFgA|aQBlAHgA|cgBlAG)/ ascii wide

  condition:
    filesize < 16777216 and any of them
}

rule powershell_format: high {
  meta:
    description = "obfuscated Powershell format string"
    author      = "Florian Roth"
    filetypes   = "ps1"

  strings:
    $ref = "}{0}\"-f " ascii wide

  condition:
    filesize < 16777216 and any of them
}
