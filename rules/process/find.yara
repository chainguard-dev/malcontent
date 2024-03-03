
rule pgrep : notable {
  meta:
	description = "Finds program in process table"
  strings:
	$ref = "pgrep" fullword
  condition:
	$ref
}
