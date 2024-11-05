rule python_exec_hex: high {
  meta:
    description = "executs code from an obfuscated data stream"

  strings:
    $hex   = /exec\(\"\\x\d{1,3}.{0,32}/
    $chars = /exec\(\"\\\d{1,3}.{0,32}/

  condition:
    any of them
}

rule python_exec_marshal: high {
  meta:
    description = "evaluates code from marshalled data"

  strings:
    $marshal = "exec(marshal.loads"
    $json    = "exec(json.loads"

  condition:
    any of them
}

rule python_exec_gzip: high {
  meta:
    description = "executes code from gzip content"

  strings:
    $ref = /exec\(.{0,32}\(gzip\.decompress\(b.{0,32}/

  condition:
    any of them
}
