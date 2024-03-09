rule powershell : notable {
  strings:
	$ref = "powershell" fullword
  condition:
	$ref
}