rule snapd: override linux {
  meta:
    description           = "snapd"
    nohup                 = "medium"
    login_records         = "medium"
    dev_mem               = "medium"
    dev_mmc               = "medium"
    busybox_runner        = "medium"
    system_log_references = "medium"
    filetypes             = "elf,so"

  strings:
    $snapd_snapd = "SNAPD_SNAPD"
    $snapd       = "snapcore/snapd"

  condition:
    filesize > 15MB and filesize < 30MB and uint32(0) == 1179403647 and any of them
}
