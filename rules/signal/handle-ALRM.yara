rule sigaction_SIGALRM {
  strings:
	$ref = "sigaction SIGALRM"
  condition:
	any of them
}