rule readelf: medium {
  meta:
    description                   = "analyzes or manipulates ELF files"
    hash_2024_antirev_nullsection = "2d9ddb7761ccdb3f3d7522cda88009fddace7e1804a25aef1e75851b8c9076aa"
    hash_2024_enumeration_linpeas = "210cbe49df69a83462a7451ee46e591c755cfbbef320174dc0ff3f633597b092"

  strings:
    $ref = "readelf" fullword

  condition:
    $ref
}
