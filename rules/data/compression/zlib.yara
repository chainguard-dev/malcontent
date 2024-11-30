rule zlib: low {
  meta:
    description = "uses zlib"

  strings:
    $ref = "zlib" fullword

  condition:
    $ref
}
