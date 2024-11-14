rule mysql: medium {
  meta:
    description = "accesses MySQL databases"

  strings:
    $ref = "mysql" fullword

  condition:
    $ref
}
