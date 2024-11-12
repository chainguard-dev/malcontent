rule pam_password_overwrite: critical {
  meta:
    description = "password authentication module may record passwords"

  strings:
    $auth        = "pam_authenticate"
    $f_orig_item = "orig_pam_set_item"
    $f_orig_auth = "orig_pam_authenticate"

  condition:
    filesize < 1MB and uint32(0) == 1179403647 and all of them
}

rule pam_password_exfil_file: high {
  meta:
    description = "password authentication module may record passwords"

  strings:
    $req_auth = "pam_authenticate"

    $o_ssh_sshd        = "sshd" fullword
    $o_ssh_usr_bin_ssh = "/usr/bin/ssh"
    $o_pampassword     = "pampassword"
    $o_LD_DEBUG        = "LD_DEBUG"
    $o_LD_AUDIT        = "LD_AUDIT"
    $o_LD_PRELOAD      = "LD_PRELOAD"

    $path_dot_path         = /\/(var|tmp|etc|lib|bin|root|Users|Library|dev|proc)[\w\/]{0,32}\/\.[\.a-z0-9\-]{1,32}/ fullword
    $path_dot_tmp_stricter = /\/tmp\/\.[a-z]\.\w\-]{1,32}/ fullword
    $path_tmp_stricter     = /\/tmp\/[a-z]{4}[a-z\/\.]{1,32}/ fullword
    $path_ext              = /\/(var|tmp|etc|lib|bin|opt|usr|root|Users|Library|dev)\/[\.\w\-]{1,32}\.(dmp|txt|out|log)/ fullword
    $path_pass             = /\/(var|tmp|etc|lib|bin|opt|usr|root|Users|Library|dev)[\w\/]{0,32}\/[\.\w\-]{0,8}pass\..{0,8}/
    $path_pass2            = /\/(var|tmp|etc|lib|bin|opt|usr|root|Users|Library|dev)[\w\/]{0,32}\/[\.\w\-]{0,8}password.{0,8}/
    $path_pass3            = /\/(var|tmp|etc|lib|bin|opt|usr|root|Users|Library|dev)[\w\/]{0,32}\/login[\.\w\-]{0,8}/
    $path_pass4            = /\/(var|tmp|etc|lib|opt|root|Users|Library|dev)[\w\/]{0,32}\/pass[\.\w\-]{0,8}/
    $path_pass5            = /\/(var|tmp|etc|lib|bin|opt|usr|root|Users|Library|dev)[\w\/]{0,32}\/sshpass[\.\w\-]{0,8}/
    $path_pass6            = /\/(var|tmp|etc|lib|bin|opt|usr|root|Users|Library|dev)[\w\/]{0,32}\/login[\.\w\-]{0,8}/

  condition:
    filesize < 1MB and uint32(0) == 1179403647 and all of ($req*) and any of ($o*) and any of ($path*)
}

rule pam_passwords_rootkit: critical {
  meta:
    description = "records passwords and installs a rootkit"

  strings:
    $req_auth = "pam_authenticate"
    $rootkit  = "rootkit"

  condition:
    filesize < 1MB and all of them
}

rule pam_get_item: high {
  meta:
    description = "gets PAM (pluggable authentication module) configuration for sshd"

  strings:
    $ref                  = "pam_get_item" fullword
    $sshd                 = "sshd" fullword
    $not_sshd             = "OpenSSH"
    $not_SSH2_MSG_KEXINIT = "SSH2_MSG_KEXINIT"

  condition:
    $ref and $sshd and none of ($not*)
}
