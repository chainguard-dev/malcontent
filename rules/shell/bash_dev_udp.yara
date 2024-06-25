
rule bash_dev_udp : high exfil {
  meta:
    description = "uses /dev/udp for network access (bash)"
    hash_2024_enumeration_linpeas = "210cbe49df69a83462a7451ee46e591c755cfbbef320174dc0ff3f633597b092"
  strings:
    $ref = "/dev/udp"
    $posixly_correct = "POSIXLY_CORRECT"
  condition:
    $ref and not $posixly_correct
}
