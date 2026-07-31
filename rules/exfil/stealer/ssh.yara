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

    // $h matches inside ".ssh/authorized_keys", so one authorized_keys reference
    // used to excuse every other .ssh path in the file. Count it instead of
    // checking for it: fire only on a .ssh reference authorized_keys does not
    // account for.
    $notsub_auth_keys = ".ssh/authorized_keys"

    // A WAF ruleset enumerates every sensitive dotfile path as an LFI pattern, so
    // it reads as a pile of .ssh references. These three keys only occur together
    // in such a bundle and none of them means anything alone, so the set is
    // required as a whole rather than member-by-member.
    $notgrp_waf_version = "\"rules_version\""
    $notgrp_waf_crs     = "crs_id"
    $notgrp_waf_attack  = "attack_attempt"

  condition:
    filesize < 10MB and $h and any of ($s*) and any of ($z*) and not all of ($notgrp_waf*) and #h > #notsub_auth_keys
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
