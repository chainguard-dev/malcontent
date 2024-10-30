rule LANG_getenv {
  meta:
    description = "Looks up language of current user"

  strings:
    $ref    = "LANG" fullword
    $getenv = "getenv"

  condition:
    all of them
}

rule LANG_node {
  meta:
    description = "Looks up language of current user"

  strings:
    $ref = "env.LANG" fullword

  condition:
    all of them
}

rule dollar_LANG {
  meta:
    description = "Looks up language of current user"

  strings:
    $ref = "$LANG" fullword

  condition:
    all of them
}
