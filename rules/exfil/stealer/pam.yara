rule pam_passwords: high {
  meta:
    description = "password authentication module may record passwords"

  strings:
    $auth = "pam_authenticate"

    $pass  = /[\w]{0,8}assword/
    $pass2 = "passwd"
    $pass3 = "verify_pass"
    $pass4 = "sshpass"

    $w_write = "write"
    $w_path  = /\/(var|tmp|etc|lib|bin|opt|usr|root|Users|Library|dev)\/[\.\w\-]{2,}/

    $f_socket        = "socket"
    $f_exfil         = "exfil"
    $f_orig_item     = "orig_pam_set_item"
    $f_orig_auth     = "orig_pam_authenticate"
    $f_getifaddrs    = "getifaddrs" fullword
    $f_keylogger     = "keylogger"
    $f_ssh           = "/bin/ssh"
    $f_sendto        = "sendto" fullword
    $f_readdir64     = "readdir64" fullword
    $f_hidden        = "hidden"
    $not_pam_service = "--pam-service"

  condition:
    filesize < 1MB and uint32(0) == 1179403647 and $auth and any of ($pass*) and all of ($w*) and any of ($f*) and none of ($not*)
}

rule pam_passwords_rootkit: critical {
  meta:
    description = "records passwords and installs a rootkit"

  strings:
    $rootkit = "rootkit"

  condition:
    any of them and pam_passwords
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
