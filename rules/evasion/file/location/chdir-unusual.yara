rule cd_tmp: medium {
  meta:
    description = "changes the current working directory to /tmp"

  strings:
    $d_tmp = "cd /tmp"

  condition:
    $d_tmp
}

rule cd_usr: medium {
  meta:
    description = "changes the current working directory to /usr"

  strings:
    $d_usr = /cd \/usr[\/\w\.]{0,16}/

  condition:
    $d_usr
}

rule cd_mnt: medium {
  meta:
    description = "changes the current working directory to /mnt"

  strings:
    $d_mnt = "cd /mnt"

  condition:
    any of ($d*)
}

rule cd_bin: high {
  meta:
    description = "changes the current working directory to bin directory"

  strings:
    $d_bin      = "cd /bin"
    $d_sbin     = "cd /sbin"
    $d_usr_bin  = "cd /usr/bin"
    $d_usr_sbin = "cd /usr/sbin"

  condition:
    any of ($d*)
}

rule cd_root: high {
  meta:
    description = "changes the current working directory to /root"

  strings:
    $d_root = "cd /root"

  condition:
    any of ($d*)
}

rule cd_var: medium {
  meta:
    description = "changes the current working directory to /var"

  strings:
    $d_usr = /cd \/var[\/\w\.]{0,16}/

  condition:
    $d_usr
}

rule cd_var_subdir: high {
  meta:
    description = "changes current working directory to /var/{log,run,tmp}"

  strings:
    $d_var_log = "cd /var/log"
    $d_var_run = "cd /var/run"
    $d_var_tmp = "cd /var/tmp"

    $not_var_log_packages = "cd /var/log/packages"

  condition:
    any of ($d*) and none of ($not*)
}

rule cd_val_obsessive: critical {
  meta:
    description = "changes directory to multiple unusual locations"

  strings:
    $d_mnt   = "cd /mnt"
    $d_root  = "cd /root"
    $d_bin   = "cd /bin"
    $d_tmp   = "cd /tmp"
    $d_dev   = "cd /dev"
    $d_slash = /cd \/[\; \|\&]/ fullword

  condition:
    3 of them
}

rule unusual_cd_dev: high {
  meta:
    description = "changes the current working directory to /dev"

  strings:
    $d_dev   = /cd \/dev\/[\w\/\.]{1,64}/
    $makedev = "MAKEDEV"

  condition:
    $d_dev and not $makedev
}
