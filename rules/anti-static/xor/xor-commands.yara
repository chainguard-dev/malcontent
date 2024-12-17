rule xor_commands: high {
  meta:
    description = "commands obfuscated using xor"

  strings:
    $b_chmod      = "chmod " xor(1-31)
    $b_curl       = "curl -" xor(1-31)
    $b_bin_sh     = "/bin/sh" xor(1-31)
    $b_bin_bash   = "/bin/bash" xor(1-31)
    $b_openssl    = "openssl" xor(1-31)
    $b_screen_dm  = "screen -" xor(1-31)
    $b_zmodload   = "zmodload" xor(1-31)
    $b_dev_tcp    = "/dev/tcp" xor(1-31)
    $b_bash_i     = "bash -i" xor(1-31)
    $b_bash_c     = "bash -c" xor(1-31)
    $b_base64     = "base64" xor(1-31)
    $b_chmod2     = "chmod " xor(33-255)
    $b_curl2      = "curl -" xor(33-255)
    $b_bin_sh2    = "/bin/sh" xor(33-255)
    $b_bin_bash2  = "/bin/bash" xor(33-255)
    $b_openssl2   = "openssl" xor(33-255)
    $b_screen_dm2 = "screen -" xor(33-255)
    $b_zmodload2  = "zmodload" xor(33-255)
    $b_dev_tcp2   = "/dev/tcp" xor(33-255)
    $b_bash_i2    = "bash -i" xor(33-255)
    $b_bash_c2    = "bash -c" xor(33-255)
    $b_base642    = "base64" xor(33-255)
    $b_xterm      = "TERM=xterm" xor(1-31)
    $b_xterm2     = "TERM=xterm" xor(33-255)

  condition:
    any of them
}
