rule qemu: override {
  meta:
    description = "QEMU"

  strings:
    $module = "QEMU_MODULE"

  condition:
    filesize < 5MB and all of them
}
