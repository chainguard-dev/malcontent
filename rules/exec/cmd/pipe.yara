rule popen: medium {
  meta:
    description = "launches program and reads its output"
    syscall     = "pipe"
    ref         = "https://linux.die.net/man/3/popen"

  strings:
    $_popen       = "_popen" fullword
    $_pclose      = "_pclose" fullword
    $os_popen     = /os.popen[\(\"\'\w \$\)]{0,32}/
    $ruby         = /IO\.popen\(["'\w \.\#\{\}]{0,64},["']r/
    $ruby2        = /Open\w{0,1}\.popen\w{0,2}\(["'\w \.\#\{\}]{0,64}/
    $pipe_glibc   = "pipe@@GLIBC"
    $pipe_generic = "cmdpipe"
    $js           = "getExecOutput" fullword

  condition:
    any of them
}

rule popen_go: medium {
  meta:
    description = "launches program and reads its output"
    syscall     = "pipe"
    ref         = "https://linux.die.net/man/3/popen"
    filetypes   = "elf,go,macho"

  strings:
    $exec = "exec"
    $co   = "CombinedOutput"

  condition:
    all of them
}
