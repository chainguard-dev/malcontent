rule env_LD_DEBUG : suspicious {
  meta:
    description = "Checks if dynamic linker debugging is enabled"
  strings:
	$val = "LD_DEBUG" fullword
  condition:
	all of them
}
