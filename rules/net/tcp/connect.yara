rule connect_tcp: medium {
  meta:
    description = "connects to a TCP port"

  strings:
    $go_tcp_listen = "dialTCP" fullword
    $ruby          = "TCPSocket.new"
    $ruby2         = "TCPSocket.open"

  condition:
    any of them
}
