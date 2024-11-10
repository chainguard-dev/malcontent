rule progname: low {
  meta:
    description                                                       = "get the current process name"
    ref                                                               = "https://linux.die.net/man/3/program_invocation_short_name"
    hash_2024_Downloads_8cad                                          = "8cad755bcf420135c0f406fb92138dcb0c1602bf72c15ed725bd3b76062dafe5"
    hash_2023_FontOnLake_771340752985DD8E84CF3843C9843EF7A76A39E7_elf = "602c435834d796943b1e547316c18a9a64c68f032985e7a5a763339d82598915"

  strings:
    $ref = "program_invocation_short_name"

  condition:
    any of them in (1000..3000)
}

rule process_name: medium {
  meta:
    description                          = "get the current process name"
    hash_2024_Downloads_0f66             = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"
    hash_2024_Downloads_4b97             = "4b973335755bd8d48f34081b6d1bea9ed18ac1f68879d4b0a9211bbab8fa5ff4"
    hash_2023_Linux_Malware_Samples_3b4e = "3b4e756212ea2ed01da98cceeb856449bb50d380339b5564e30cbe7fbfdae2d4"

  strings:
    $ref  = "processName"
    $ref2 = "process_name"

  condition:
    any of them
}
