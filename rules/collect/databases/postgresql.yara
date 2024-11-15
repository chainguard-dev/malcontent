rule postgresql: medium {
  meta:
    description = "accesses PostgreSQL databases"

  strings:
    $ref  = "postgresql" fullword
    $ref2 = "github.com/go-pg" fullword

  condition:
    any of them
}
