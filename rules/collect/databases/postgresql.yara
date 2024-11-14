rule postgresql: medium {
  meta:
    description               = "accesses PostgreSQL databases"
    hash_2023_0xShell_adminer = "2fd7e6d8f987b243ab1839249551f62adce19704c47d3d0c8dd9e57ea5b9c6b3"

  strings:
    $ref  = "postgresql" fullword
    $ref2 = "github.com/go-pg" fullword

  condition:
    any of them
}
