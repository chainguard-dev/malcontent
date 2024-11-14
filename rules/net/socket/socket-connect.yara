rule _connect: medium {
  meta:
    description = "initiate a connection on a socket"
    syscall     = "connect"
    ref         = "https://linux.die.net/man/3/connect"

  strings:
    $connect  = "_connect" fullword
    $connectx = "_connectx" fullword

  condition:
    any of them
}

rule connect: medium {
  meta:
    description                    = "initiate a connection on a socket"
    syscall                        = "connect"
    ref                            = "https://linux.die.net/man/3/connect"
    hash_2018_test_connect_asynct  = "d477e83e87219cb2890b04672c192f23fe3fd2cd277884135545775c0ac1e378"
    hash_2018_test_readable_asynct = "e155cc7ae149699f1c4563f9837010ef1a5fba8e9e58ebd653735f83a404df44"

  strings:
    $connect = "connect" fullword

  condition:
    any of them in (1000..3000)
}

rule py_connect: medium {
  meta:
    description             = "initiate a connection on a socket"
    syscall                 = "connect"
    ref                     = "https://docs.python.org/3/library/socket.html"
    hash_2023_libcurl_setup = "5deef153a6095cd263d5abb2739a7b18aa9acb7fb0d542a2b7ff75b3506877ac"

    hash_2020_Enigma = "6b2ff7ae79caf306c381a55409c6b969c04b20c8fda25e6d590e0dadfcf452de"

  strings:
    $socket = "socket.socket"
    $ref    = ".connect("

  condition:
    all of them
}

rule php_connect: medium {
  meta:
    description = "initiate a connection on a socket"
    syscall     = "connect"
    ref         = "https://www.php.net/manual/en/function.fsockopen.php"

    hash_2024_systembc_password = "236cff4506f94c8c1059c8545631fa2dcd15b086c1ade4660b947b59bdf2afbd"
    hash_2024_ciscotools_4247   = "42473f2ab26a5a118bd99885b5de331a60a14297219bf1dc1408d1ede7d9a7a6"

  strings:
    $ref = "fsockopen"

  condition:
    any of them
}
