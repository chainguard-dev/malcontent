rule password_finder_generic : suspicious {
  meta:
	description = "password finder or dumper"
  strings:
	$ref = "findPassword"
	$ref2 = "find_password"
  condition:
	any of them
}

rule password_dumper_generic : suspicious {
  meta:
	description = "password dumper"
  strings:
	$ref3 = "dumpPassword"
	$ref4 = "dump_password"
  condition:
	any of them
}
