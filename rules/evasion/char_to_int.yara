
rule js_char_code_at : high {
  meta:
    description = "converts strings into integers"
	filetypes = "javascript"
  strings:
    $charCodeAt = "charCodeAt" fullword
	$index = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/="
  condition:
    any of them
}
