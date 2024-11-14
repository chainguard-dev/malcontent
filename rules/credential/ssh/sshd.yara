rule sshd: medium {
  meta:
    description = "Mentions SSHD"

  strings:
    $ref = "sshd" fullword

  condition:
    $ref
}

rule sshd_path_value: high {
  meta:
    description = "Mentions the SSH daemon by path"

  strings:
    $ref = "/usr/bin/sshd" fullword

  condition:
    $ref
}

rule sshd_net: high {
  meta:
    description = "Mentions SSHD network processes"

  strings:
    $ref  = "sshd: [net]"
    $ref2 = "sshd: [accepted]"

  condition:
    any of them
}

rule sshd_proc: high {
  meta:
    description = "Mentions SSHD proces"

  strings:
    $ref  = "sshdproc"
    $ref2 = "sshd_proc"

  condition:
    filesize < 1MB and any of them
}
