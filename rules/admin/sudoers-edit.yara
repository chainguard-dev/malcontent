
rule sudo_editor : suspicious {
  meta:
    description = "references /etc/sudoers"
  strings:
    $etc_sudoers = "/etc/sudoers"
    $nopasswd = "NOPASSWD:"
    $not_sample = "sudoers man page"
    $not_vim = "VIMRUNTIME"
  condition:
    filesize < 5242880 and ($etc_sudoers or $nopasswd) and none of ($not*)
}
