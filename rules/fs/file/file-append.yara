rule append_file {
  meta:
    pledge      = "wpath"
    description = "appends to a file"

  strings:
    $ref1 = "appendFile" fullword

  condition:
    any of them
}
