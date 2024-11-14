rule xz_command: medium {
  meta:
    description = "command shells out to xz"

  strings:
    $ref = "xz -"

  condition:
    $ref
}

rule xz_lib: medium {
  meta:
    description = "uses xz library"

  strings:
    $ref = "ulikunitz/xz"

  condition:
    $ref
}
