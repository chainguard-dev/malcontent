rule dev_dm: medium linux {
  meta:
    capability  = "CAP_SYS_RAWIO"
    description = "access raw LVM disk mapper devices"

  strings:
    $val = /\/dev\/dm-[\$%\w\{\}]{0,10}/

  condition:
    any of them
}
