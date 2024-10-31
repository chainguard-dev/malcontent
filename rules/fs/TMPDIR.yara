rule TMPDIR {
  strings:
    $ref    = "TMPDIR" fullword
    $getenv = "getenv"

  condition:
    all of them
}
