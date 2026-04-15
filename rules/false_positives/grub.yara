rule grub_boot_images: override {
  meta:
    description     = "GRUB i386-pc boot images"
    single_load_rwe = "medium"

  strings:
    $grub = "GRUB"

  condition:
    filesize < 64KB and $grub
}
