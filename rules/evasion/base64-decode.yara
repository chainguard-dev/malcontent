rule base64_decode : suspicious python {
  meta:
	description = "decodes base64 strings"
  strings:
	$b64decode = "b64decode"
  condition:
	any of them
}
