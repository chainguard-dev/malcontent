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


    hash_2024_ciscotools_4247   = "42473f2ab26a5a118bd99885b5de331a60a14297219bf1dc1408d1ede7d9a7a6"

  strings:
    $ref = "fsockopen"

  condition:
    any of them
}
