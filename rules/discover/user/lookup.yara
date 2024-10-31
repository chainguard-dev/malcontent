rule getpwuid: harmless {
  meta:
    description = "get entry from passwd (user) database"

  strings:
    $ref  = "getpwuid" fullword
    $ref2 = "getpwent" fullword
    $ref3 = "getpwnam" fullword
    $ref4 = "getpwuuid" fullword
    $ref5 = "setpassen" fullword
    $ref6 = "endpwent" fullword
    $ref7 = "user/lookup" fullword

  condition:
    any of them
}
