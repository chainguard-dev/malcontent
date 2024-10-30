rule cmd_dev_null: medium {
  meta:
    description                          = "runs commands, discards output"
    hash_2023_Linux_Malware_Samples_a07b = "a07bd8aedde27e776480bb375d191ce11c3a03275f6a03616b4a0bfbc1b9dfe6"
    hash_2023_Linux_Malware_Samples_ee22 = "ee22d8b31eecf2c7dd670dde075df199be44ef4f61eb869f943ede7f5c3d61cb"
    hash_2021_CDDS_installer_v2021       = "cf5edcff4053e29cb236d3ed1fe06ca93ae6f64f26e25117d68ee130b9bc60c8"

  strings:
    $ref  = /"{0,1}%s"{0,1} {0,2}[12&]{0,1}> {0,1}\/dev\/null/
    $ref2 = "\"%s\" >/dev/null"

  condition:
    any of them
}
