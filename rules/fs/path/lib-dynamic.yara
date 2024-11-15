rule dyntamic_lib: medium {
  meta:
    description = "References a library file that can be generated dynamically"

  strings:
    $ref = "/lib/%s"

  condition:
    $ref
}
