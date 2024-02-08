rule sigaction_SIGINFO {
  strings:
	$ref = "sigaction SIGINFO"
  condition:
	any of them
}