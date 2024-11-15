rule base64_commands: high {
  meta:
    description = "commands in base64 form"

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
