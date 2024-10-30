rule plugin {
  meta:
    description = "references a 'plugin'"

  strings:
    $ref  = /[a-zA-Z_ ]{0,32}[pP]lugin[\w ]{0,8}/ fullword
    $ref2 = /[pP]lugin[a-zA-Z_]{0,16}/ fullword

  condition:
    any of ($ref*)
}
