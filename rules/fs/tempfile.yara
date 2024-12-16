rule mktemp {
  meta:
    description = "creates temporary files"

  strings:
    $ref  = "mktemp" fullword
    $ref2 = "temp file"
    $ref3 = "ioutil/tempfile"
    $ref4 = "tmpfile"
    $ref5 = "createTempFile"

  condition:
    any of them
}
