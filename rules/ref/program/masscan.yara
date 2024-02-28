rule masscan : notable {
  strings:
	$ref = "masscan" fullword
  condition:
	$ref
}