rule sql: low {
  meta:
    description = "accesses SQL databases"

  strings:
    $ref = "SQL" fullword

  condition:
    any of them
}
