rule masscan : suspicious {
  strings:
	$ref = "masscan" fullword
  condition:
	$ref
}