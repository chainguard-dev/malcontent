rule chr: medium {
  meta:
    description = "assembles strings from UTF-16 code units"

  strings:
    $ref = /.{0,8}fromCharCode.{0,8}/

  condition:
    any of them
}
