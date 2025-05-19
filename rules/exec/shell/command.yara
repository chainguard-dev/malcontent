rule system: medium {
  meta:
    description = "execute a shell command"
    syscalls    = "fork,execl"
    ref         = "https://man7.org/linux/man-pages/man3/system.3.html"

    filetypes = "elf,macho"

  strings:
    $system = "system" fullword

  condition:
    all of them in (1000..3000)
}

rule generic: medium {
  meta:
    description = "run a command"

  strings:
    $runCommand  = "runCommand" fullword
    $RUN_COMMAND = "RUN_COMMAND" fullword

  condition:
    any of them
}

rule generic_shell_exec: medium {
  meta:
    description = "execute a shell command"

    filetypes = "php"

  strings:
    $exec = "shell_exec"

  condition:
    any of them
}

rule php_shell_exec: medium php {
  meta:
    description = "execute a shell command"
    syscalls    = "fork,execl"

    filetypes = "php"

  strings:
    $php = "<?php"
    $ref = /shell_exec[\(\$\w\)]{0,16}/

  condition:
    filesize < 200KB and $php and $ref
}
