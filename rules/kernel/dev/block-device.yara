
rule block_devices : medium linux {
  meta:
    description = "works with block devices"
    hash_2023_Linux_Malware_Samples_1020 = "1020ce1f18a2721b873152fd9f76503dcba5af7b0dd26d80fdb11efaf4878b1a"
    hash_2023_Linux_Malware_Samples_206c = "206cc0d26617057196f1e3e8903597fd0b234c9f945263fad9ac6b1686c71d21"
    hash_2023_Linux_Malware_Samples_24f3 = "24f3ac76dcd4b0830a1ebd82cc9b1abe98450b8df29cb4f18f032f1077d24404"
  strings:
    $sys_val = /\/sys\/block[\$%\w\{\}]{0,16}/
    $sys_dev_val = /\/sys\/dev\/block[\$%\w\{\}]{0,16}/
  condition:
    any of them
}

rule dev_sd : medium linux {
  meta:
    capability = "CAP_SYS_RAWIO"
    description = "access raw generic block devices"
  strings:
    $val = /\/dev\/sd[\$%\w\{\}]{0,10}/
  condition:
    any of them
}
