rule b64 {
  meta:
    description = "Supports base64 encoded strings"

  strings:
    $base64   = "base64"
    $certutil = "certutil -decode"

  condition:
    any of them
}
