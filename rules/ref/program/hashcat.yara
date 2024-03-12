rule hashcat : notable {
  strings:
	$ref = "hashcat" fullword
  condition:
	$ref
}