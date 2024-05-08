
rule load_agent_with_payload : suspicious {
  strings:
    $loadAgent = "loadAgent"
    $payload = "payload"
    $not_private = "/System/Library/PrivateFrameworks/"
  condition:
    $payload and $loadAgent and none of ($not*)
}
