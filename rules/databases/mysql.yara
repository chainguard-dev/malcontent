
rule mysql : notable {
  meta:
	description = "accesses MySQL databases"
  strings:
    $ref = "mysql" fullword
  condition:
	$ref
}