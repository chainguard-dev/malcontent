rule selinux_firewall : suspicious{
  meta:
	description = "fetches file, makes it executable, runs it"
  strings:
	$ref = "curl" fullword
	$ref2 = "chmod" fullword
	$ref3 = /\.\/[a-z\/]{0,32}/ fullword
  condition:
	all of them
}
