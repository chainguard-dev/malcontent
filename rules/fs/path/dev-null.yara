rule dev_null: harmless {
  meta:
    description = "References /dev/null"

  strings:
    $ref = "/dev/null"

  condition:
    any of them
}
