rule grub_boot_images: override {
  meta:
    description     = "GRUB i386-pc boot images (boot.image, boot_hybrid.image)"
    single_load_rwe = "medium"

  strings:
    $grub = "GRUB"

  condition:
    filesize < 64KB and $grub
}

rule grub_cdboot_image: override {
  meta:
    description     = "GRUB i386-pc CD boot image"
    single_load_rwe = "medium"

  strings:
    $cdrom_fail = "cdrom read fails"
    $no_boot    = "no boot info"

  condition:
    filesize < 8KB and all of them
}

rule grub_diskboot_image: override {
  meta:
    description     = "GRUB i386-pc disk boot image"
    single_load_rwe = "medium"

  strings:
    $blocklist    = "blocklist_default_start"
    $notification = "notification_string"

  condition:
    filesize < 8KB and all of them
}

rule grub_lnxboot_image: override {
  meta:
    description     = "GRUB i386-pc Linux boot image"
    single_load_rwe = "medium"

  strings:
    $move_mem = "move memory fails"
    $setup    = "setup_sects"

  condition:
    filesize < 8KB and all of them
}

rule grub_pxeboot_image: override {
  meta:
    description     = "GRUB i386-pc PXE boot image"
    single_load_rwe = "medium"

  strings:
    // PXE boot stub: mov dl,0x7f followed by far jump to 0x0000:0x8200
    $pxe_entry = { b2 7f ea 00 82 00 00 }

  condition:
    filesize < 4096 and $pxe_entry
}
