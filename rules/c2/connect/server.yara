rule connect_server: medium {
  meta:
    description = "connects to a server"

  strings:
    $ = "connected to server" fullword

  condition:
    filesize < 1MB and any of them
}

