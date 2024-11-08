rule spctl_master_disable: critical {
  meta:
    description = "disables macOS Gatekeeper"

  strings:
    $ref = "spctl --master-disable"

  condition:
    $ref
}
