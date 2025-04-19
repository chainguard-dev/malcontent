rule http: low {
  meta:
    pledge      = "inet"
    description = "Uses the HTTP protocol"

  strings:
    $ref  = "http" fullword
    $ref2 = "HTTP"

  condition:
    any of them
}
