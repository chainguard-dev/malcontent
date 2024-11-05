rule python_eval_hex: high {
  meta:
    description = "evaluates code from an obfuscated data stream"

  strings:
    $hex   = /eval\(\"\\x\d{1,3}.{0,32}/
    $chars = /eval\(\"\\\d{1,3}.{0,32}/

  condition:
    any of them
}

rule python_eval_marshal: high {
  meta:
    description = "evaluates code from marshalled data"

  strings:
    $marshal = "eval(marshal.loads"
    $json    = "eval(json.loads"

  condition:
    any of them
}

rule python_eval_gzip: high {
  meta:
    description = "evaluates code from gzip content"

  strings:
    $ref = /eval\(.{0,32}\(gzip\.decompress\(b.{0,32}/

  condition:
    any of them
}
