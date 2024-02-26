rule linpeas : suspicious {
  strings:
	$ref = "linpeas" fullword
  condition:
	$ref
}