rule pipe_to_shell: medium {
  meta:
    description = "pipes to shell"

  strings:
    $val_sh       = "| sh"
    $val_bin_sh   = "| /bin/sh"
    $val_bash     = "| bash"
    $val_bin_bash = "| /bin/bash"

  condition:
    any of them
}
