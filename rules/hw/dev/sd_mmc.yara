rule dev_mmc: high {
  meta:
    capability  = "CAP_SYS_RAWIO"
    description = "access raw SD/MMC devices"

  strings:
    $dev_mmc   = /\/dev\/mmcblk[\$%\w\{\}]{0,16}/
    $dev_block = /\/dev\/block\/mmcblk[\$%\w\{\}]{0,16}/

  condition:
    filesize < 10MB and any of ($dev*)
}

rule dev_mmc_ok: override {
  meta:
    dev_mmc = "medium"

  strings:
    $not_fwupd = "fu_firmware_set_id"
    $not_ipmi  = "/dev/ipmi"
    $not_grub  = "GRUB" fullword

  condition:
    dev_mmc and any of them
}
