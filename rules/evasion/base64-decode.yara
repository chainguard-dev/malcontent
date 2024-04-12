rule base64_decode : notable python {
  meta:
	description = "decodes base64 strings"
  strings:
	$b64decode = "b64decode"
  condition:
	any of them
}

rule urlsafe_decode64 : notable ruby {
  meta:
	description = "decodes base64 strings"
  strings:
	$urlsafe_decode64_ruby = "urlsafe_decode64"
  condition:
	any of them
}
