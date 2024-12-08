rule http_accept_json: low {
  meta:
    pledge      = "inet"
    description = "accepts JSON files via HTTP"

  strings:
    $ref   = "Accept" fullword
    $mime  = "application/json"
    $mime2 = "application/ld+json"

  condition:
    $ref and any of ($mime*)
}

rule http_accept_binary: medium {
  meta:
    pledge      = "inet"
    description = "accepts binary files via HTTP"

  strings:
    $ref   = "Accept" fullword
    $mime2 = "application/octet-stream"

  condition:
    $ref and any of ($mime*)
}
