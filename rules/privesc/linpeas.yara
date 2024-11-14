rule linpeas: high {
  meta:
  strings:
    $ref = "linpeas" fullword

  condition:
    $ref
}
