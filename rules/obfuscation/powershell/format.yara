rule powershell_format: high {
  meta:
    description = "obfuscated Powershell format string"
    author      = "Florian Roth"

  strings:
    $ref = "}{0}\"-f " ascii wide

  condition:
    filesize < 16777216 and any of them
}
