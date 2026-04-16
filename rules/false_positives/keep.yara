rule keep_ui_tweetnacl: override {
  meta:
    description                  = "keep-ui Next.js server chunk containing bundled tweetnacl crypto library"
    from_secret_key              = "low"
    unsigned_bitwise_math_excess = "low"

  strings:
    $nacl_box_keypair = "crypto_box_keypair"
    $nacl_secretbox   = "nacl.secretbox"
    $sentry           = "_sentryDebugIds"

  condition:
    filesize < 1048576 and all of them
}
