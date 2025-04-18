rule linux_multi_persist: high {
  meta:
    description = "references multiple Linux persistence methods"

  strings:
    $o_initd     = /etc\/init\.d\/[\w\/\.]{0,32}/ fullword
    $o_udev      = "etc/udev"
    $o_crontab   = "crontab" fullword
    $o_xdg       = "[Desktop Entry]"
    $o_rc_d      = "/etc/rc.d/rc.local"
    $o_insmod    = "insmod" fullword
    $o_preload   = "/etc/ld.so.preload"
    $o_systemctl = "systemctl"

    $bash_ref  = ".bash_profile"
    $bash_ref2 = ".profile" fullword
    $bash_ref3 = ".bashrc" fullword
    $bash_ref4 = ".bash_logout"
    $bash_ref5 = "/etc/profile"
    $bash_ref6 = "/etc/bashrc"
    $bash_ref7 = "/etc/bash"

    $not_shell        = "POSIXLY_CORRECT" fullword
    $not_vim          = "VIMRUNTIME" fullword
    $not_appsec_rules = "\"id\": \"crs-930-120\""

  condition:
    filesize < 20MB and 3 of ($o*) and any of ($bash*) and none of ($not*)
}
