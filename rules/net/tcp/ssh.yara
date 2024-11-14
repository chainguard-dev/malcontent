rule ssh: medium {
  meta:
    description = "Supports SSH (secure shell)"

  strings:
    $ = "SSH" fullword
    $ = "ssh_packet" fullword
    $ = "secureShellClient"

  condition:
    any of them
}

rule crypto_ssh: medium {
  meta:
    description = "Uses crypto/ssh to connect to the SSH (secure shell) service"

  strings:
    $go = "crypto/ssh" fullword

  condition:
    any of them
}
