rule recvmsg {
  meta:
    description = "receive a message from a socket"
    ref         = "https://linux.die.net/man/2/recvmsg"

  strings:
    $recvmsg  = "recvmsg" fullword
    $recvfrom = "recvfrom" fullword
    $_recv    = "_recv" fullword

  condition:
    any of them
}

rule recv {
  meta:
    description = "receive a message to a socket"
    syscall     = "recv"
    ref         = "https://linux.die.net/man/2/recv"

  strings:
    $send   = "recv" fullword
    $socket = "socket" fullword

  condition:
    all of them
}
