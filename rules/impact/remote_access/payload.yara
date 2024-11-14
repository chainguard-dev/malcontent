rule load_agent_with_payload: high {
  meta:
    hash_2020_FinSpy_installer = "80d6e71c54fb3d4a904637e4d56e108a8255036cbb4760493b142889e47b951f"

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
