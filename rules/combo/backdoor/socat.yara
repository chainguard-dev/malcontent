rule socat_backdoor : high {
  strings:
	$socat = "socat" fullword
	$bin_bash = "/bin/bash"
	$pty = "pty" fullword
  condition:
	all of them
}
