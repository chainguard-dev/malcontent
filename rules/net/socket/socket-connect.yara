rule _connect: medium {
  meta:
    description              = "initiate a connection on a socket"
    syscall                  = "connect"
    ref                      = "https://linux.die.net/man/3/connect"
    hash_2023_Downloads_016a = "016a1a4fe3e9d57ab0b2a11e37ad94cc922290d2499b8d96957c3ddbdc516d74"
    hash_2024_Downloads_036a = "036a2f04ab56b5e7098c7d866eb21307011b812f126793159be1c853a6a54796"
    hash_2024_Downloads_0ca7 = "0ca7e0eddd11dfaefe0a0721673427dd441e29cf98064dd0f7b295eae416fe1b"

  strings:
    $connect  = "_connect" fullword
    $connectx = "_connectx" fullword

  condition:
    any of them
}

rule connect: medium {
  meta:
    description                                                                          = "initiate a connection on a socket"
    syscall                                                                              = "connect"
    ref                                                                                  = "https://linux.die.net/man/3/connect"
    hash_2018_test_connect_asynct                                                        = "d477e83e87219cb2890b04672c192f23fe3fd2cd277884135545775c0ac1e378"
    hash_2018_test_readable_asynct                                                       = "e155cc7ae149699f1c4563f9837010ef1a5fba8e9e58ebd653735f83a404df44"
    hash_2024_Downloads_0fa8a2e98ba17799d559464ab70cce2432f0adae550924e83d3a5a18fe1a9fc8 = "503fcf8b03f89483c0335c2a7637670c8dea59e21c209ab8e12a6c74f70c7f38"

  strings:
    $connect = "connect" fullword

  condition:
    any of them in (1000..3000)
}

rule py_connect: medium {
  meta:
    description                 = "initiate a connection on a socket"
    syscall                     = "connect"
    ref                         = "https://docs.python.org/3/library/socket.html"
    hash_2023_libcurl_setup     = "5deef153a6095cd263d5abb2739a7b18aa9acb7fb0d542a2b7ff75b3506877ac"
    hash_2024_aaa_bbb_ccc_setup = "5deef153a6095cd263d5abb2739a7b18aa9acb7fb0d542a2b7ff75b3506877ac"
    hash_2020_Enigma            = "6b2ff7ae79caf306c381a55409c6b969c04b20c8fda25e6d590e0dadfcf452de"

  strings:
    $socket = "socket.socket"
    $ref    = ".connect("

  condition:
    all of them
}

rule php_connect: medium {
  meta:
    description                  = "initiate a connection on a socket"
    syscall                      = "connect"
    ref                          = "https://www.php.net/manual/en/function.fsockopen.php"
    hash_2023_0xShell_0xShellori = "506e12e4ce1359ffab46038c4bf83d3ab443b7c5db0d5c8f3ad05340cb09c38e"
    hash_2024_systembc_password  = "236cff4506f94c8c1059c8545631fa2dcd15b086c1ade4660b947b59bdf2afbd"
    hash_2024_ciscotools_4247    = "42473f2ab26a5a118bd99885b5de331a60a14297219bf1dc1408d1ede7d9a7a6"

  strings:
    $ref = "fsockopen"

  condition:
    any of them
}
