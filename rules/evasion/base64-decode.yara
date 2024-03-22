rule base64_decode : suspicious python {
  meta:
	description = "decodes base64 strings"
  strings:
	$b64decode = "b64decode"
	$urlsafe_decode64_ruby = "urlsafe_decode64"
  condition:
	any of them
}
