
rule generic_obfuscated_perl : suspicious {
  strings:
    $unpack_nospace = "pack'" fullword
    $unpack = "pack '" fullword
    $unpack_paren = "pack(" fullword
    $reverse = "reverse "
    $sub = "sub "
    $eval = "eval{"
  condition:
    filesize < 20971520 and $eval and 3 of them
}

rule powershell_format : suspicious {
  meta:
    description = "obfuscated Powershell format string"
    author = "Florian Roth"
  strings:
    $ref = "}{0}\"-f " ascii wide
  condition:
    filesize < 16777216 and any of them
}

rule powershell_compact : notable windows {
  meta:
    description = "unusually compact PowerShell representation"
    author = "Florian Roth"
  strings:
    $InokeExpression = ");iex" ascii wide nocase
  condition:
    filesize < 16777216 and any of them
}

rule casing_obfuscation : notable windows {
  meta:
    description = "unusual casing obfuscation"
    author = "Florian Roth"
  strings:
    $ref = /  (sEt|SEt|SeT|sET|seT)  / ascii wide
  condition:
    filesize < 16777216 and any of them
}

rule powershell_encoded : suspicious windows {
  meta:
    description = "Encoded Powershell"
    author = "Florian Roth"
  strings:
    $ref = / -[eE][decoman]{0,41} ['"]?(JAB|SUVYI|aWV4I|SQBFAFgA|aQBlAHgA|cgBlAG)/ ascii wide
  condition:
    filesize < 16777216 and any of them
}
