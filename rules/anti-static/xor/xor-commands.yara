
rule xor_commands : high {
  meta:
    description = "commands obfuscated using xor"
    hash_2023_Linux_Trojan_ShellBot_accc = "acccf2fa4e21f2cd1d7305186e4c83d6cde5ee98f1b37022b70170533e399a89"
    hash_2023_ZIP_locker_AArch_64 = "724eb1c8e51f184495cfe81df7049531d413dd3e434ee3506b6cc6b18c61e96d"
    hash_2023_ZIP_locker_ARMv5_32 = "0a2bffa0a30ec609d80591eef1d0994d8b37ab1f6a6bad7260d9d435067fb48e"
  strings:
    $b_chmod = "chmod " xor(1-31)
    $b_curl = "curl -" xor(1-31)
    $b_bin_sh = "/bin/sh" xor(1-31)
    $b_bin_bash = "/bin/bash" xor(1-31)
    $b_openssl = "openssl" xor(1-31)
    $b_dev_null = "/dev/null" xor(1-31)
    $b_usr_bin = "/usr/bin" xor(1-31)
    $b_usr_sbin = "/usr/sbin" xor(1-31)
    $b_var_tmp = "/var/tmp" xor(1-31)
    $b_var_run = "/var/run" xor(1-31)
    $b_screen_dm = "screen -" xor(1-31)
    $b_zmodload = "zmodload" xor(1-31)
    $b_dev_tcp = "/dev/tcp" xor(1-31)
    $b_bash_i = "bash -i" xor(1-31)
    $b_bash_c = "bash -c" xor(1-31)
    $b_base64 = "base64" xor(1-31)
    $b_eval = "eval(" xor(1-31)
    $b_chmod2 = "chmod " xor(33-255)
    $b_curl2 = "curl -" xor(33-255)
    $b_bin_sh2 = "/bin/sh" xor(33-255)
    $b_bin_bash2 = "/bin/bash" xor(33-255)
    $b_openssl2 = "openssl" xor(33-255)
    $b_dev_null2 = "/dev/null" xor(33-255)
    $b_usr_bin2 = "/usr/bin" xor(33-255)
    $b_usr_sbin2 = "/usr/sbin" xor(33-255)
    $b_var_tmp2 = "/var/tmp" xor(33-255)
    $b_var_run2 = "/var/run" xor(33-255)
    $b_screen_dm2 = "screen -" xor(33-255)
    $b_zmodload2 = "zmodload" xor(33-255)
    $b_dev_tcp2 = "/dev/tcp" xor(33-255)
    $b_bash_i2 = "bash -i" xor(33-255)
    $b_bash_c2 = "bash -c" xor(33-255)
    $b_base642 = "base64" xor(33-255)
    $b_eval2 = "eval(" xor(33-255)
  condition:
    any of ($b_*)
}
