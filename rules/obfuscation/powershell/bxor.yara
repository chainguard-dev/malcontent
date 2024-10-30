rule casing_obfuscation: critical {
  meta:
    description = "powershell byte XOR"

  strings:
    $ps_powershell = "powershell"
    $ps_bytes      = "[System.IO.File]"
    $xor           = "-bxor" fullword

  condition:
    filesize < 16KB and $xor and any of ($ps*)
}
