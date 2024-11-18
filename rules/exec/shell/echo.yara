rule elf_calls_shell_echo: medium {
  meta:
    syscall     = "posix_spawn"
    pledge      = "exec"
    description = "program generates text with echo command"
    ref         = "https://linux.die.net/man/1/echo"

  strings:
    $val      = /echo ['"%\w\\>\/ \.]{1,64}/
    $not_echo = "not echo"

  condition:
    uint32(0) == 1179403647 and $val and none of ($not*)
}
