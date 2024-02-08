rule sigaction_SIGINT {
  strings:
	$ref = "sigaction SIGINT"
  condition:
	any of them
}