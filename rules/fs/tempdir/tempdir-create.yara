rule mkdtemp {
  meta:
    description = "creates temporary directory"
    pledge      = "wpath"

  strings:
    $mkdtemp = "mkdtemp" fullword
    $tempdir = "temp dir"

  condition:
    any of them
}
