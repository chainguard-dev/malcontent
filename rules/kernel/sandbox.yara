rule sandbox: harmless {
  meta:
    description = "uses macOS sandboxing facilities"

  strings:
    $ref  = "sandbox_extension_consume"
    $ref2 = "SANDBOX_EXTENSION_DEFAULT"

  condition:
    any of them
}
