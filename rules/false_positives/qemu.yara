rule qemu: override {
  meta:
    description    = "QEMU"
    proc_d_cmdline = "medium"
    ESET_Moose_2   = "harmless"

  strings:
    $module  = "QEMU_MODULE"
    $aligned = "QEMU_IS_ALIGNED"

  condition:
    filesize < 30MB and any of them
}
