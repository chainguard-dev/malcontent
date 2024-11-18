rule py_ssl_socket: medium {
  meta:
    description = "manually encrypts a socket with SSL"

  strings:
    $ref1 = /\.wrap_socket\([\w\.,= \)]{2,64}/
    $ref2 = "ssl" fullword

  condition:
    all of them
}

