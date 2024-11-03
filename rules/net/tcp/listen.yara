rule listen_tcp: medium {
  meta:
    description = "listen on a TCP port"

  strings:
    $go_tcp_listen = "_net.(*TCPListener).Accept"
    $listen        = "listening on tcp"

  condition:
    any of them
}
