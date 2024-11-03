rule _access: harmless {
  meta:
    description = "check if the current user can access a file"

  strings:
    $_access    = "_access" fullword
    $faccessat  = "faccessat" fullword
    $faccessat2 = "faccessat2" fullword

  condition:
    any of them
}

rule access: harmless {
  meta:
    description = "check if the current user can access a file"

  strings:
    $access = "access" fullword

  condition:
    all of them in (1000..3000)
}
