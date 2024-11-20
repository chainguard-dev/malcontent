rule load_agent_with_payload: high {
  meta:
    description = "loads agent with payload"

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

rule obfuscated_payload: high {
  meta:
    description = "contains an obfuscated payload"

  strings:
    $decode64_payload = "decode64(payload)"
    $json_payload     = "JSON.parse(payload)"

  condition:
    any of them
}

rule eval_payload: high {
  meta:
    description = "evaluates code from a remote payload"

  strings:
    $eval_payload = /(eval|exec)\(payload[\[\]\"\w\)]{0,16}/

  condition:
    any of them
}
