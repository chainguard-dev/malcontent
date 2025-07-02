rule snapd: override linux {
  meta:
    description           = "snapd"
    nohup                 = "medium"
    dev_mem               = "medium"
    dev_mmc               = "medium"
    busybox_runner        = "medium"
    system_log_references = "medium"
    hidden_x11_unexpected = "medium"
    filetypes             = "elf,so"

  strings:
    $snapd_snapd = "SNAPD_SNAPD"
    $snapd       = "snapcore/snapd"
    $snapd_debug = "SNAPD_DEBUG"
    $snap_name   = "SNAP_NAME" fullword

  condition:
    filesize > 1MB and filesize < 30MB and uint32(0) == 1179403647 and any of them
}
