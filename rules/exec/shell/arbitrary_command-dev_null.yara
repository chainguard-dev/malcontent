rule cmd_dev_null: medium {
  meta:
    description = "runs commands, discards output"

  strings:
    $ref  = /"{0,1}%s"{0,1} {0,2}[12&]{0,1}> {0,1}\/dev\/null/
    $ref2 = "\"%s\" >/dev/null"

  condition:
    any of them
}
