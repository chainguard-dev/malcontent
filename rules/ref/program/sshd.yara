
rule sshd : notable {
  meta:
    description = "Mentions SSHD"
  strings:
    $ref = "sshd" fullword
  condition:
    $ref
}

rule sshd_path_value : suspicious {
  meta:
    description = "Mentions the SSH daemon by path"
    hash_2023_Unix_Trojan_WINNTI_3b37 = "3b378846bc429fdf9bec08b9635885267d8d269f6d941ab1d6e526a03304331b"
  strings:
    $ref = "/usr/bin/sshd" fullword
  condition:
    $ref
}

rule sshd_net : suspicious {
  meta:
    description = "Mentions SSHD network processes"
  strings:
    $ref = "sshd: [net]"
    $ref2 = "sshd: [accepted]"
  condition:
    any of them
}
