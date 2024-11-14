rule sqlite: medium {
  meta:
    description = "accesses SQLite databases"

  strings:
    $ref  = "sqlite" fullword
    $ref3 = "sqlite3" fullword

  condition:
    any of them
}
