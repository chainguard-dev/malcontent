rule base64_commands: high {
  meta:
    description                          = "commands in base64 form"
    hash_2023_OrBit_f161                 = "f1612924814ac73339f777b48b0de28b716d606e142d4d3f4308ec648e3f56c8"
    hash_2023_Sysrv_Hello_sys_x86_64     = "cd784dc1f7bd95cac84dc696d63d8c807129ef47b3ce08cd08afb7b7456a8cd3"
    hash_2023_Unix_Downloader_Rocke_228e = "228ec858509a928b21e88d582cb5cfaabc03f72d30f2179ef6fb232b6abdce97"

  strings:
    $b_chmod        = "chmod" base64
    $b_curl         = "curl -" base64
    $b_bin_sh       = "/bin/sh" base64
    $b_bin_bash     = "/bin/bash" base64
    $b_openssl      = "openssl" base64
    $b_dev_null     = "/dev/null" base64
    $b_usr_bin      = "/usr/bin" base64
    $b_usr_sbin     = "/usr/sbin" base64
    $b_var_tmp      = "/var/tmp" base64
    $b_var_run      = "/var/run" base64
    $b_screen_dm    = "screen -" base64
    $b_zmodload     = "zmodload" base64
    $b_dev_tcp      = "/dev/tcp" base64
    $b_bash_i       = "bash -i" base64
    $b_tar_c        = "tar -c" base64
    $b_tar_x        = "tar -x" base64
    $b_bash_c       = "bash -c" base64
    $b_type_nul     = "type nul" base64
    $not_kandji     = "kandji-parameter-agent"
    $not_mdmprofile = "mdmprofile"
    $not_example    = "commands are encoded"

  condition:
    any of ($b_*) and none of ($not_*)
}

rule base64_suspicious_commands: critical {
  meta:
    description = "suspicious commands in base64 form"

  strings:
    $exec_redirect_all = "exec &>/dev/null" base64
    $date_checksum     = "date|md5sum|head -c20" base64
    $tmp_ICE_unix      = "tmp/.ICE-unix" base64
    $curl              = "curl -m60 -fksLA-" base64
    $bash_tcp          = "exec 3<>/dev/tcp/" base64
    $chmod_x           = "chmod +x" base64
    $rm_f              = "&& rm -f " base64
    $sock5h_url        = "socks5h://" base64

  condition:
    filesize < 64KB and any of them
}
