rule nmap : suspicious {
  strings:
	$ref = "nmap" fullword
  condition:
	$ref
}