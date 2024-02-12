
rule base64_commands : suspicious {
  meta:
	description = "commands in base64 form"
  strings:
    $b_chmod = "chmod" base64
    $b_curl = "curl -" base64
    $b_bin_sh = "/bin/sh" base64
    $b_bin_bash = "/bin/bash" base64
    $b_openssl = "openssl" base64
    $b_dev_null = "/dev/null" base64
    $b_usr_bin = "/usr/bin" base64
    $b_usr_sbin = "/usr/sbin" base64
    $b_var_tmp = "/var/tmp" base64
    $b_var_run = "/var/run" base64
    $b_screen_dm = "screen -" base64
    $b_zmodload = "zmodload" base64
    $b_dev_tcp = "/dev/tcp" base64
    $b_bash_i = "bash -i" base64
    $b_bash_c = "bash -c" base64
    $not_kandji = "kandji-parameter-agent"
    $not_mdmprofile = "mdmprofile"
  condition:
    any of ($b_*) and none of ($not_*)
}