rule sshd_config: medium {
  meta:
    description = "accesses sshd configuration"

  strings:
    $ref     = "/etc/ssh/sshd_config"
    $not_ssh = "OpenSSH"

  condition:
    filesize < 100MB and $ref and none of ($not*)
}

rule sshd_config_alter: high {
  meta:
    description = "alters password authentication config in sshd"

  strings:
    $r_sshd_config = "/etc/ssh/sshd_config"
    $r_fwrite      = "fwrite"
    $r_usepam      = "UsePAM"
    $r_passwd      = "PasswordAuthentication"
    $not_ssh       = "OpenSSH"

  condition:
    filesize < 5MB and all of ($r*) and none of ($not*)
}
