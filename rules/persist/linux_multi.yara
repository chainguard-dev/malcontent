rule linux_multi_persist: high {
  meta:
    description = "references multiple Linux persistence methods"

  strings:
    $initd   = /etc\/init\.d\/[\w\/\.]{0,32}/ fullword
    $udev    = "etc/udev"
    $crontab = "crontab" fullword

    $bash_ref  = ".bash_profile"
    $bash_ref2 = ".profile" fullword
    $bash_ref3 = ".bashrc" fullword
    $bash_ref4 = ".bash_logout"
    $bash_ref5 = "/etc/profile"
    $bash_ref6 = "/etc/bashrc"
    $bash_ref7 = "/etc/bash"

    $not_shell = "POSIXLY_CORRECT" fullword

  condition:
    filesize < 20MB and ($initd or $udev) and $crontab and any of ($bash*) and none of ($not*)
}
