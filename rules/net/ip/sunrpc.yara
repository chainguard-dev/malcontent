rule sunrpc: medium {
  meta:
    description = "Uses SunRPC / XDR"

  strings:
    $ref  = "xdr_bytes" fullword
    $ref2 = "Incompatible versions of RPC"

  condition:
    any of them
}
