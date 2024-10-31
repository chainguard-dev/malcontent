rule tmpdir {
  strings:
    $ref    = "TEMP" fullword
    $getenv = "getenv"

  condition:
    all of them
}
