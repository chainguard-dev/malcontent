
rule sudo_editor : high {
  meta:
    description = "references /etc/sudoers"
    hash_2017_MacOS_AppStore = "4131d4737fe8dfe66d407bfd0a0df18a4a77b89347471cc012da8efc93c661a5"
    hash_2018_org_logind_ctp_archive_helper2 = "af4ad3b8bf81a877a47ded430ac27fdcb3ddd33d3ace52395f76cbdde46dbfe0"
  strings:
    $etc_sudoers = "/etc/sudoers"
    $nopasswd = "NOPASSWD:"
    $not_sample = "sudoers man page"
    $not_vim = "VIMRUNTIME"
  condition:
    filesize < 5242880 and ($etc_sudoers or $nopasswd) and none of ($not*)
}
