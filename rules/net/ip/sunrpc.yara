rule sunrpc: medium {
  meta:
    description              = "Uses SunRPC / XDR"
    hash_2024_Downloads_a031 = "a031da66c6f6cd07343d5bc99cc283528a5b7f04f97b2c33c2226a388411ec61"

  strings:
    $ref  = "xdr_bytes" fullword
    $ref2 = "Incompatible versions of RPC"

  condition:
    any of them
}
