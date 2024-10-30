rule dev_mtd: medium linux {
  meta:
    capability  = "CAP_SYS_RAWIO"
    description = "access raw flash memory devices"

  strings:
    $val       = /\/dev\/mtd[\$%\w\{\}]{0,16}/
    $block_val = /\/dev\/block\/mtdblock[\$%\w\{\}]{0,16}/

  condition:
    any of them
}
