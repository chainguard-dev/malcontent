
rule calls_shell : medium {
  meta:
    description = "executes shell"
    hash_2023_0xShell_wesoori = "bab1040a9e569d7bf693ac907948a09323c5f7e7005012f7b75b5c1b2ced10ad"
    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
    hash_2023_Downloads_06ab = "06abc46d5dbd012b170c97d142c6b679183159197e9d3f6a76ba5e5abf999725"
  strings:
    $bin_sh = "/bin/sh"
    $bin_bash = "/bin/bash"
    $bin_dash = "/bin/dash"
    $bin_zsh = "/bin/zsh"
    $sh_val = /\/bin\/sh[ \%\{\}\$\-\"\'][ \%\{\}\$\-\w\"\']{1,64}/
    $bash_val = /\/bin\/bash[ \%\{\}\$\-\"\'][ \%\{\}\$\-\w\"\']{1,64}/
    $dash_val = /\/bin\/dash[ \%\{\}\$\-\"\'][ \%\{\}\$\-\w\"\']{1,64}/
    $zsh_val = /\/bin\/zsh[ \%\{\}\$\-\"\'][ \%\{\}\$\-\w\"\']{1,64}/
  condition:
    filesize < 104857600 and any of them
}
