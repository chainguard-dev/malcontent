rule sendmsg {
  meta:
    description = "send a message to a socket"
    syscall     = "sendmsg,sendto"
    ref         = "https://linux.die.net/man/2/sendmsg"

  strings:
    $sendmsg  = "sendmsg" fullword
    $sendto   = "sendto" fullword
    $_send    = "_send" fullword
    $sendmmsg = "sendmmsg" fullword

  condition:
    any of them
}

rule send {
  meta:
    description = "send a message to a socket"
    ref         = "https://linux.die.net/man/2/send"
    syscall     = "send"

  strings:
    $send   = "send" fullword
    $socket = "socket" fullword

  condition:
    all of them
}
