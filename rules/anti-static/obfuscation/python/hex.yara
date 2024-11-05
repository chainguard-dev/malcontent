rule python_long_hex: medium {
  meta:
    description = "contains a large hexadecimal string variable"
    filetypes   = "py"

  strings:
    $assign = /\w{0,16}=["'][a-z0-9]{1024}/

  condition:
    filesize < 1MB and $assign
}

rule python_long_hex_multiple: high {
  meta:
    description = "contains multiple large hexadecimal string variables"
    filetypes   = "py"

  strings:
    $assign = /\w{0,16}=["'][a-z0-9]{1024}/

  condition:
    filesize < 1MB and #assign > 3
}
