rule env_LD_PROFILE : notable {
  meta:
    description = "Checks if dynamic linker profiling is enabled"
  strings:
	$val = "LD_PROFILE" fullword
  condition:
	all of them
}
