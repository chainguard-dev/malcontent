rule sudo_editor: medium {
  meta:
    description                              = "references /etc/sudoers"
    hash_2017_MacOS_AppStore                 = "4131d4737fe8dfe66d407bfd0a0df18a4a77b89347471cc012da8efc93c661a5"
    hash_2018_org_logind_ctp_archive_helper2 = "af4ad3b8bf81a877a47ded430ac27fdcb3ddd33d3ace52395f76cbdde46dbfe0"
    hash_2024_scripts_ld                     = "41967393b2c1e645456d59dabb3837f605dd30b9c4a72aaebaf51ecc572d24bd"

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
