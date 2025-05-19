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
    description = "initiate a connection on a socket"
    syscall     = "connect"
    ref         = "https://linux.die.net/man/3/connect"

  strings:
    $connect = "connect" fullword

  condition:
    any of them in (1000..3000)
}

rule py_connect: medium {
  meta:
    description = "initiate a connection on a socket"
    syscall     = "connect"
    ref         = "https://docs.python.org/3/library/socket.html"
    filetypes   = "py"

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
    filetypes   = "php"

  strings:
    $ref = "fsockopen"

  condition:
    any of them
}
