rule tar_ssh_net: medium {
  meta:
    description = "possible tar-based SSH stealer"

  strings:
    $s_curl   = "curl" fullword
    $s_wget   = "wget" fullword
    $s_socket = "socket" fullword
    $h        = ".ssh" fullword
    $z_zip    = "zip" fullword
    $z_tar    = "tar" fullword
    $z_xargs  = "xargs cat"

    $not_auth_keys = ".ssh/authorized_keys"

  condition:
    filesize < 10MB and $h and any of ($s*) and any of ($z*) and none of ($not*)
}

rule curl_https_ssh: high {
  meta:
    description = "possible curl-based SSH stealer"

  strings:
    $curl   = "curl" fullword
    $ssh    = ".ssh" fullword
    $id_rsa = "id_rsa"
    $http   = "http://"
    $https  = "https://"

  condition:
    filesize < 15KB and $curl and $ssh and $id_rsa and any of ($http*)
}

rule stealssh: critical {
  meta:
    description = "SSH stealer"

  strings:
    $folder    = ".ssh" fullword
    $steal     = "stealssh"
    $stealSSH  = "stealSSH"
    $steal_ssh = "steal_ssh"

  condition:
    filesize < 10MB and $folder and any of ($steal*)
}

rule sshd_tmp_policy: high {
  meta:
    description = "adjusts sshd tmp policy, possibly to dump credentials"

  strings:
    $unconfined = "unconfined_u:object_r:sshd_tmp_t:s0"

  condition:
    any of them
}

rule ssh_pass_file: high {
  meta:
    description = "may store SSH passwords"

  strings:
    $unconfined = /sshpass\w\.txt/

  condition:
    any of them
}
