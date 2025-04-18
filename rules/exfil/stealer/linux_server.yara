rule linux_server_stealer: high {
  meta:
    description = "may steal sensitive Linux secrets"

  strings:
    $bash_history = ".bash_history"

    $other_root_ssh = "/root/.ssh"
    $other_id_rsa   = ".ssh/id_rsa"
    $other_shadow   = "etc/shadow"

    $term_crypto  = "crypto" fullword
    $term_echo    = "echo" fullword
    $term_chmod   = "chmod" fullword
    $term_find    = "find" fullword
    $term_scp     = "scp" fullword
    $term_tar     = "tar" fullword
    $term_crontab = "crontab" fullword
    $term_http    = "http" fullword

    $not_appsec_rules = "\"id\": \"crs-930-120\""

  condition:
    filesize < 10MB and $bash_history and any of ($other*) and any of ($term*) and none of ($not*)
}
