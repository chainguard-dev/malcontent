rule http2 {
  meta:
    pledge      = "inet"
    description = "Uses the HTTP/2 protocol"

  strings:
    $ref = "HTTP/2" fullword

  condition:
    any of them
}
