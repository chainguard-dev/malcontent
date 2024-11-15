rule readelf: medium {
  meta:
    description = "analyzes or manipulates ELF files"

  strings:
    $ref = "readelf" fullword

  condition:
    $ref
}
