
rule js_char_code_at : high {
  meta:
    description = "converts strings into integers"
	filetypes = "javascript"
  strings:
    $charCodeAt = "fromCharCode" fullword
  condition:
    any of them
}
