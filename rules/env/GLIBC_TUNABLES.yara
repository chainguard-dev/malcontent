rule glibc_tunables : notable {
  strings:
	$ref = "GLIBC_TUNABLES"
  condition:
	any of them
}
