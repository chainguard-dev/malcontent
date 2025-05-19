rule disable_verify: medium {
  meta:
    description = "disables SSL verification"
    filetypes   = "py"

  strings:
    $ref1 = /verify_mode.{0,8}ssl\.CERT_NONE/
    $ref2 = "ssl" fullword

  condition:
    all of them
}
