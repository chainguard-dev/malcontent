rule sigaction_SIGHUP {
  strings:
	$ref = "sigaction SIGHUP"
  condition:
	any of them
}