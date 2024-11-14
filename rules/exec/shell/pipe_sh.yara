rule pipe_to_shell: medium {
  meta:
    description              = "pipes to shell"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2024_Downloads_a031 = "a031da66c6f6cd07343d5bc99cc283528a5b7f04f97b2c33c2226a388411ec61"

  strings:
    $val_sh       = "| sh"
    $val_bin_sh   = "| /bin/sh"
    $val_bash     = "| bash"
    $val_bin_bash = "| /bin/bash"

  condition:
    any of them
}
