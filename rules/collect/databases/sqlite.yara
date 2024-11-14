rule sqlite: medium {
  meta:
    description = "accesses SQLite databases"

    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2024_Downloads_0f66 = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"

  strings:
    $ref  = "sqlite" fullword
    $ref3 = "sqlite3" fullword

  condition:
    any of them
}
