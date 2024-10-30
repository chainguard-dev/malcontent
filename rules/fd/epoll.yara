rule epoll: linux {
  meta:
    description = "I/O event notification facility"
    pledge      = "stdio"
    ref         = "https://linux.die.net/man/7/epoll"

  strings:
    $ref  = "epoll_wait" fullword
    $ref2 = "epoll_create" fullword

  condition:
    any of them
}
