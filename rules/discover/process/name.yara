rule progname: low {
  meta:
    description              = "get the current process name"
    ref                      = "https://linux.die.net/man/3/program_invocation_short_name"
    hash_2024_Downloads_8cad = "8cad755bcf420135c0f406fb92138dcb0c1602bf72c15ed725bd3b76062dafe5"

  strings:
    $ref = "program_invocation_short_name"

  condition:
    any of them in (1000..3000)
}

rule process_name: medium {
  meta:
    description              = "get the current process name"
    hash_2024_Downloads_0f66 = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"
    hash_2024_Downloads_4b97 = "4b973335755bd8d48f34081b6d1bea9ed18ac1f68879d4b0a9211bbab8fa5ff4"

  strings:
    $ref  = "processName"
    $ref2 = "process_name"

  condition:
    any of them
}
