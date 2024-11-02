rule listen_tcp: medium {
  meta:
    description = "connects to a TCP port"

  strings:
    $go_tcp_listen = "dialTCP" fullword

  condition:
    any of them
}
