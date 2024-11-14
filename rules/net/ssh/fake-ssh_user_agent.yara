rule fake_openssh_0: high {
  meta:
    description = "Contains OpenSSH user-agent, possibly for spoofing purposes"

  strings:
    $ref = /SSH-2\.0-OpenSSH_[\w\.]{0,8}/

  condition:
    $ref
}
