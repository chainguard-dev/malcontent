rule python_reads_itself: high {
  meta:
    description = "python file reads itself, possibly hiding additional instructions"
    filetype    = "py"

  strings:
    $ref = "open(__file__," fullword

  condition:
    filesize < 1MB and any of them
}
