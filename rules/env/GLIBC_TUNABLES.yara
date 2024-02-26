rule glibc_tunables : suspicious {
  strings:
	$ref = "GLIBC_TUNABLES"
  condition:
	any of them
}
