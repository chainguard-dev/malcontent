rule ssh: medium {
  meta:
    description = "Supports SSH (secure shell)"


    hash_1985_deploy             = "8729e61daf18a196f7571fa097be32dd7b4dbcc3e3794be1102aa2ad91f4cbe0"

  strings:
    $ = "SSH" fullword
    $ = "ssh_packet" fullword
    $ = "secureShellClient"

  condition:
    any of them
}

rule crypto_ssh: medium {
  meta:
    description              = "Uses crypto/ssh to connect to the SSH (secure shell) service"



  strings:
    $go = "crypto/ssh" fullword

  condition:
    any of them
}
