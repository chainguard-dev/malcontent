rule tmpdir {
  strings:
	$ref = "TMPDIR" fullword
	$getenv = "getenv"
  condition:
	all of them
}
