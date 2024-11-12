rule pam_passwords: medium {
  meta:
    description = "contains password authentication module"

  strings:
    $auth       = "pam_authenticate"
    $pass       = "password"
    $not_libpam = "Linux-PAM" fullword
    $not_sshd   = "OpenSSH" fullword

  condition:
    $auth and $pass and none of ($not*)
}
