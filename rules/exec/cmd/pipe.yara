rule popen: medium {
  meta:
    description = "launches program and reads its output"
    syscall     = "pipe"
    ref         = "https://linux.die.net/man/3/popen"

  strings:
    $_popen       = "_popen" fullword
    $_pclose      = "_pclose" fullword
    $os_popen     = /os.popen[\(\"\'\w \$\)]{0,32}/
    $pipe_glibc   = "pipe@@GLIBC"
    $pipe_generic = "cmdpipe"

  condition:
    any of them
}
