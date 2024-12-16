rule cmd_dev_null: medium {
  meta:
    description = "runs templated commands, discards output"

  strings:
    $ref  = /%s {1,2}[12&]{0,1}> {0,1}\/dev\/null/
    $ref2 = "\"%s\" >/dev/null"

  condition:
    any of them
}

rule cmd_dev_null_quoted: high {
  meta:
    description = "runs quoted templated commands, discards output"

  strings:
    $ref  = /"%s" {0,2}[12&]{0,1}> {0,1}\/dev\/null/
    $ref2 = "\"%s\" >/dev/null"
    $ref3 = /.{0,64} %s 2\>\/dev\/null/

  condition:
    any of them
}
