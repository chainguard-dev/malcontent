rule dumb_int_compares: high {
  meta:
    description = "compares arbitrary integers, likely encoding something"
    filetypes   = "py"

  strings:
    $import              = "import" fullword
    $decode_or_b64decode = /if \d{2,16} == \d{2,16}/

  condition:
    filesize < 1MB and all of them
}
