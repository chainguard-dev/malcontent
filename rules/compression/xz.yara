
rule xz_command : notable {
  meta:
	description = "command shells out to xz"
  strings:
    $ref = "xz -"
  condition:
	$ref
}

rule xz_lib : notable {
  meta:
	description = "uses xz library"
  strings:
    $ref = "ulikunitz/xz"
  condition:
	$ref
}