rule python_exec_hex: high {
  meta:
    description                  = "executs code from an obfuscated data stream"

  strings:
	$eval_hex = /exec\(\"\\x\d{1,3}.{0,32}/
	$eval_chars = /exec\(\"\\\d{1,3}.{0,32}/

  condition:
	any of them
}
