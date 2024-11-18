rule exists: low {
  meta:
    description = "check if a file exists"

  strings:
    $ref = "path.exists" fullword

  condition:
    any of them
}
