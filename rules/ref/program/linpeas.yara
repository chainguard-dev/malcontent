rule linpeas : high {
  strings:
	$ref = "linpeas" fullword
  condition:
	$ref
}