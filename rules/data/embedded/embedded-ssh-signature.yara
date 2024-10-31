rule ssh_signature: medium {
  meta:
    description = "Contains embedded SSH signature"

  strings:
    $sig = "--BEGIN SSH SIGNATURE--"

  condition:
    any of them
}

