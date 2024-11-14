rule load_agent_with_payload: high {
  meta:
  strings:
    $loadAgent   = "loadAgent"
    $payload     = "payload"
    $not_private = "/System/Library/PrivateFrameworks/"

  condition:
    filesize < 10MB and $payload and $loadAgent and none of ($not*)
}

rule payload_path: high {
  strings:
    $payload_path  = "payload_path"
    $other_payload = /\w{0,16}payload\w{0,16}/
    $not_private   = "/System/Library/PrivateFrameworks/"

  condition:
    filesize < 10MB and $payload_path and $other_payload and none of ($not*)
}
