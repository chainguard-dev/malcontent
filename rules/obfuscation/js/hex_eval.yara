rule js_hex_eval_obfuscation: critical {
  meta:
    description = "javascript eval bfuscation (hex)"

  strings:
    $return = /\(eval, _{0,4}0x[\w]{0,32}[\(\[]/

  condition:
    filesize < 128KB and any of them
}
