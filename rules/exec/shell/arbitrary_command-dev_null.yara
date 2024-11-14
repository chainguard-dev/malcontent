rule cmd_dev_null: medium {
  meta:
    description = "runs commands, discards output"

    hash_2021_CDDS_installer_v2021 = "cf5edcff4053e29cb236d3ed1fe06ca93ae6f64f26e25117d68ee130b9bc60c8"

  strings:
    $ref  = /"{0,1}%s"{0,1} {0,2}[12&]{0,1}> {0,1}\/dev\/null/
    $ref2 = "\"%s\" >/dev/null"

  condition:
    any of them
}
