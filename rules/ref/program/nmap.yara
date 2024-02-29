rule nmap : notable {
  strings:
	$ref = "nmap" fullword
  condition:
	$ref
}