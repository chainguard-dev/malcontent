
rule xor_commands : suspicious {
  meta:
	description = "commands obfuscated using xor"
  strings:
    $b_chmod = "chmod" xor(1-255)
    $b_curl = "curl -" xor(1-255)
    $b_bin_sh = "/bin/sh" xor(1-255)
    $b_bin_bash = "/bin/bash" xor(1-255)
    $b_openssl = "openssl" xor(1-255)
    $b_dev_null = "/dev/null" xor(1-255)
    $b_usr_bin = "/usr/bin" xor(1-255)
    $b_usr_sbin = "/usr/sbin" xor(1-255)
    $b_var_tmp = "/var/tmp" xor(1-255)
    $b_var_run = "/var/run" xor(1-255)
    $b_screen_dm = "screen -" xor(1-255)
    $b_zmodload = "zmodload" xor(1-255)
    $b_dev_tcp = "/dev/tcp" xor(1-255)
    $b_bash_i = "bash -i" xor(1-255)
    $b_bash_c = "bash -c" xor(1-255)
    $not_kandji = "kandji-parameter-agent"
    $not_mdmprofile = "mdmprofile"
  condition:
    any of ($b_*) and none of ($not_*)
}