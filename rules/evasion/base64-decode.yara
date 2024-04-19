rule base64_decode : notable python {
  meta:
	description = "decode base64 strings"
  strings:
	$b64decode = "b64decode"
  condition:
	any of them
}

rule urlsafe_decode64 : notable ruby {
  meta:
	description = "decode base64 strings"
  strings:
	$urlsafe_decode64_ruby = "urlsafe_decode64"
  condition:
	any of them
}

rule powershell_decode : notable {
  meta:
	description = "decode base64 strings"
  strings:
	$ref = "[System.Convert]::FromBase64String" ascii
  condition:
	any of them
}
