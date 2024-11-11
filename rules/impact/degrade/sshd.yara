rule sshd_config: low {
  meta:
    description = "accesses sshd configuration"

  strings:
    $ref            = "/etc/ssh/sshd_config"
    $not_ssh        = "OpenSSH"
    $not_Dockerfile = "Dockerfile"
    $not_procmail   = "procmail"
    $not_vim        = "VIMRUNTIME"

  condition:
    filesize < 10MB and $ref and none of ($not*)
}

rule sshd_config_alter: high {
  meta:
    description = "alters password authentication config in sshd"

  strings:
    $r_sshd_config = "/etc/ssh/sshd_config"
    $r_fwrite      = "write"
    $r_usepam      = "UsePAM"
    $r_passwd      = "PasswordAuthentication"
    $not_ssh       = "OpenSSH"
    $not_vim       = "VIMRUNTIME"

  condition:
    filesize < 5MB and all of ($r*) and none of ($not*)
}
