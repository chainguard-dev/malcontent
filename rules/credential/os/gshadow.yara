rule etc_gshadow: medium {
  meta:
    description = "accesses /etc/gshadow (group passwords)"

  strings:
    $ref = "etc/gshadow"

  condition:
    any of them
}
