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

    hash_2024_src_tracers = "5e774902d99c93cf4e7441a8a7d5674966ee6ca72760779639bbf3a9a9a3e065"

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
