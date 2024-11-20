rule getpeername {
  meta:
    description = "get peer address of connected socket"
    syscall     = "getpeername"
    ref         = "https://man7.org/linux/man-pages/man2/getpeername.2.html"

  strings:
    $ref         = "getpeername" fullword
    $client_addr = /client_addr[\w]{0,8}/

  condition:
    any of them
}
