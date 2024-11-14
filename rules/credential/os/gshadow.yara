rule etc_gshadow: medium {
  meta:
    description                   = "accesses /etc/gshadow (group passwords)"
    hash_2024_dumpcreds_3snake    = "6f2ec2921dd8da2a9bbc4ca51060b2c5f623b0e8dc904e23e27b9574f991848b"
    hash_2024_enumeration_linpeas = "210cbe49df69a83462a7451ee46e591c755cfbbef320174dc0ff3f633597b092"

  strings:
    $ref = "etc/gshadow"

  condition:
    any of them
}
