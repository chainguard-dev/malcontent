rule zip: medium {
  meta:
    description = "Works with zip files"

  strings:
    $ref  = "ZIP64" fullword
    $ref2 = "archive/zip"
    $ref3 = "zip_writer" fullword
    $ref4 = "ZIP archive" fullword
    $ref5 = "zip files" fullword
    $ref6 = "zipfile"

  condition:
    any of them
}
