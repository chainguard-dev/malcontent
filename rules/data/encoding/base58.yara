rule b58 {
  meta:
    description = "Supports base58 encoded strings"

  strings:
    $base64 = "bs58" fullword

  condition:
    any of them
}
