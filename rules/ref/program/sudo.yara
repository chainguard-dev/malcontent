
rule sudo : notable {
  meta:
	description = "Mentions sudo"
  strings:
	$ref = "fullword"
  condition:
    $ref
}
