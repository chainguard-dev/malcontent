rule world_writeable_dirs: medium {
  meta:
    description = "mentions multiple world writeable directories"

  strings:
    $tmp_tmp        = /\/tmp[\w\.\/]{0,32}/ fullword
    $tmp_dev_shm    = /\/dev\/shm[\w\.\/]{0,32}/
    $tmp_dev_mqueue = /\/dev\/mqueue[\w\.\/]{0,32}/
    $tmp_var_tmp    = /\/var\/tmp[\w\.\/]{0,32}/

  condition:
    filesize < 20MB and 3 of them
}

rule world_writeable_dirs_chmod: high {
  meta:
    description = "mentions chmod and multiple world writeable directories"

  strings:
    $tmp_tmp        = /\/tmp[\w\.\/]{0,32}/ fullword
    $tmp_dev_shm    = /\/dev\/shm[\w\.\/]{0,32}/
    $tmp_dev_mqueue = /\/dev\/mqueue[\w\.\/]{0,32}/
    $tmp_var_tmp    = /\/var\/tmp[\w\.\/]{0,32}/
    $chmod          = "chmod" fullword

  condition:
    filesize < 256KB and $chmod and 3 of ($tmp*)
}

rule world_writeable_dirs_tiny: high {
  meta:
    description = "small program mentions multiple world writeable directories"

  strings:
    $tmp_tmp        = /\/tmp[\w\.\/]{0,32}/ fullword
    $tmp_dev_shm    = /\/dev\/shm[\w\.\/]{0,32}/
    $tmp_dev_mqueue = /\/dev\/mqueue[\w\.\/]{0,32}/
    $tmp_var_tmp    = /\/var\/tmp[\w\.\/]{0,32}/

  condition:
    filesize < 1KB and 3 of them
}
