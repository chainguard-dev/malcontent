rule popen: medium {
  meta:
    description                 = "launches program and reads its output"
    syscall                     = "pipe"
    ref                         = "https://linux.die.net/man/3/popen"
    hash_2023_libcurl_setup     = "5deef153a6095cd263d5abb2739a7b18aa9acb7fb0d542a2b7ff75b3506877ac"
    hash_2024_aaa_bbb_ccc_setup = "5deef153a6095cd263d5abb2739a7b18aa9acb7fb0d542a2b7ff75b3506877ac"
    hash_2024_Downloads_0f66    = "0f66a4daba647486d2c9d838592cba298df2dbf38f2008b6571af8a562bc306c"

  strings:
    $_popen       = "_popen" fullword
    $_pclose      = "_pclose" fullword
    $os_popen     = /os.popen[\(\"\'\w \$\)]{0,32}/
    $pipe_glibc   = "pipe@@GLIBC"
    $pipe_generic = "cmdpipe"

  condition:
    any of them
}
