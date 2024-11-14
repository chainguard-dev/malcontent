rule sudo_editor: medium {
  meta:
    description = "references /etc/sudoers"

  strings:
    $etc_sudoers = "/etc/sudoers"
    $nopasswd    = "NOPASSWD:"
    $not_sample  = "sudoers man page"
    $not_vim     = "VIMRUNTIME"

  condition:
    filesize < 5242880 and ($etc_sudoers or $nopasswd) and none of ($not*)
}

rule small_elf_sudoer: high {
  meta:
    description = "references /etc/sudoers"

  condition:
    uint32(0) == 1179403647 and filesize < 10MB and sudo_editor
}

rule sudo_parser: override {
  meta:
    small_elf_sudoer = "medium"

  strings:
    $parse = "sudo_parse"

  condition:
    uint32(0) == 1179403647 and filesize < 10MB and all of them
}
