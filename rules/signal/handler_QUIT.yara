rule sigaction_SIGQUIT {
  strings:
	$ref = "sigaction SIGQUIT"
  condition:
	any of them
}