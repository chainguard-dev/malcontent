rule bash_dev_udp: medium exfil {
  meta:
    description                   = "uses /dev/udp for network access (bash)"
    hash_2024_enumeration_linpeas = "210cbe49df69a83462a7451ee46e591c755cfbbef320174dc0ff3f633597b092"

  strings:
    $ref = "/dev/udp"

  condition:
    $ref
}

rule bash_dev_udp_high: high exfil {
  meta:
    description                   = "uses /dev/udp for network access (bash)"
    hash_2024_enumeration_linpeas = "210cbe49df69a83462a7451ee46e591c755cfbbef320174dc0ff3f633597b092"

  strings:
    $ref                 = "/dev/udp"
    $not_posixly_correct = "POSIXLY_CORRECT"
    $not_dd              = "dd if=/dev/zero"
    $not_echo            = "echo > /dev/udp"

  condition:
    filesize < 1KB and $ref and none of ($not*)
}
