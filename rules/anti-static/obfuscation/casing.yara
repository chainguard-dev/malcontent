rule casing_obfuscation: medium windows {
  meta:
    description = "unusual casing obfuscation"
    author      = "Florian Roth"
    filetypes   = "ps1"

  strings:
    $ref = /  (sEt|SEt|SeT|sET|seT)  / ascii wide

  condition:
    filesize < 1MB and any of them
}

rule set_variable_variable_casing: high windows {
  meta:
    description = "Set-Item case obfuscation"
    filetypes   = "ps1"

  strings:
    $ref  = /[Ss][eE][tT]-[vV][aA][rR][iI][aA][bB][Ll][eE]/
    $not  = "Set-Variable"
    $not2 = "SET-VARIABLE"
    $not3 = "set-variable"
    $not4 = "set-Variable"
    $not5 = "Set-variable"

  condition:
    filesize < 1MB and $ref and none of ($not*)
}

rule set_item_variable_casing: high windows {
  meta:
    description = "Set-Item case obfuscation"
    filetypes   = "ps1"

  strings:
    $ref  = /[Ss][eE][tT]-[Ii][Tt][Ee][Mm]/
    $not  = "Set-Item"
    $not2 = "SET-ITEM"
    $not3 = "set-item"
    $not4 = "set-Item"
    $not5 = "Set-item"

  condition:
    filesize < 1MB and $ref and none of ($not*)
}

rule string_variable_casing: high windows {
  meta:
    description = "[string] case obfuscation"
    filetypes   = "ps1"

  strings:
    $ref  = /\[[Ss][Tt][Rr][Ii][Nn][Gg]\]/
    $not  = "[string]"
    $not2 = "[STRING]"
    $not3 = "[String]"

  condition:
    filesize < 1MB and $ref and none of ($not*)
}

rule length_casing: medium windows {
  meta:
    description = "length case obfuscation"
    filetypes   = "ps1"

  strings:
    $ref  = /\.[Ll][Ee][Nn][Gg][Tt][Hh]/
    $not  = "Length"
    $not2 = "length"
    $not3 = "LENGTH"

  condition:
    filesize < 1MB and $ref and none of ($not*)
}

rule pshome_casing: high windows {
  meta:
    description = "PSHOME case obfuscation"
    filetypes   = "ps1"

  strings:
    $ref  = /[Pp][Ss][Hh][Oo][Mm][Ee]/ fullword
    $not  = "PSHOME"
    $not2 = "pshome"
    $not3 = "Pshome"

  condition:
    filesize < 1MB and $ref and none of ($not*)
}

rule variable_casing: high windows {
  meta:
    description = "Variable case obfuscation"
    filetypes   = "ps1"

  strings:
    $ref  = /[Vv][Aa][Rr][Ii][Aa][Bb][Ll][Ee]/ fullword
    $not  = "variable"
    $not2 = "Variable"
    $not3 = "VARIABLE"

  condition:
    filesize < 1MB and $ref and none of ($not*)
}

rule pshome_multiple_casing: critical windows {
  meta:
    description = "Multiple forms of case obfuscation"
    filetypes   = "ps1"

  strings:
    $ref  = /[Pp][Ss][Hh][Oo][Mm][Ee]/ fullword
    $not  = "PSHOME"
    $not2 = "pshome"
    $not3 = "Pshome"

  condition:
    filesize < 1MB and ($ref and none of ($not*)) and (string_variable_casing or set_item_variable_casing or length_casing)
}

rule string_multiple_casing: critical windows {
  meta:
    description = "Multiple forms of case obfuscation"
    filetypes   = "ps1"

  strings:
    $ref  = /\[[Ss][Tt][Rr][Ii][Nn][Gg]\]/
    $not  = "[string]"
    $not2 = "[STRING]"
    $not3 = "[String]"

  condition:
    filesize < 1MB and ($ref and none of ($not*)) and (string_variable_casing or set_item_variable_casing or length_casing or set_variable_variable_casing)
}
