rule getgrent: medium {
  meta:
    description = "get entry from group database"

  strings:
    $ref  = "getgrent" fullword
    $ref4 = "getgruuid" fullword
    $ref5 = "setgroupent" fullword
    $ref6 = "setgrent" fullword
    $ref7 = "endgrent" fullword

  condition:
    any of them
}

rule getgrgid_nam: harmless {
  meta:
    description = "get entry from group database"

  strings:
    $ref2 = "getgrnam" fullword
    $ref3 = "getgrgid" fullword

  condition:
    any of them
}
