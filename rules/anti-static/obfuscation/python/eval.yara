
rule python_eval_hex: high {
  meta:
    description                  = "evaluates code from an obfuscated data stream"

  strings:
	$eval_hex = /eval\(\"\\x\d{1,3}.{0,32}/
	$eval_chars = /eval\(\"\\\d{1,3}.{0,32}/

  condition:
	any of them
}
