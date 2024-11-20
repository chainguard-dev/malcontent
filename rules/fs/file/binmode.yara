rule ruby_binmode: medium {
  meta:
    description = "writes to files in binary mode"

  strings:
    $ref = /\.binmode/ fullword

  condition:
    any of them
}
