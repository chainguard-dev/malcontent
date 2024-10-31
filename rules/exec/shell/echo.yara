rule elf_calls_shell_echo: medium {
  meta:
    syscall                  = "posix_spawn"
    pledge                   = "exec"
    description              = "program generates text with echo command"
    ref                      = "https://linux.die.net/man/1/echo"
    hash_2024_Downloads_8cad = "8cad755bcf420135c0f406fb92138dcb0c1602bf72c15ed725bd3b76062dafe5"
    hash_2024_Downloads_a031 = "a031da66c6f6cd07343d5bc99cc283528a5b7f04f97b2c33c2226a388411ec61"
    hash_2023_Downloads_d920 = "d920dec25946a86aeaffd5a53ce8c3f05c9a7bac44d5c71481f497de430cb67e"

  strings:
    $val      = /echo ['"%\w\>\/ \.]{1,64}/
    $not_echo = "not echo"

  condition:
    uint32(0) == 1179403647 and $val and none of ($not*)
}
