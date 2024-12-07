rule mktemp {
  meta:
    description = "Uses mktemp to create temporary files"

  strings:
    $ref  = "mktemp" fullword
    $ref2 = "temp file"
    $ref3 = "ioutil/tempfile"
    $ref4 = "createTempFile"

  condition:
    any of them
}
