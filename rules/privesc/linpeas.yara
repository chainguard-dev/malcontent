rule linpeas: high {
  meta:
    description = "searches for opportunities for privilege escalation"

  strings:
    $ref = "linpeas" fullword

  condition:
    $ref
}
