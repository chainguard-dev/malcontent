rule socat_backdoor : suspicious {
  strings:
	$socat = "socat" fullword
	$bin_bash = "/bin/bash"
	$pty = "pty" fullword
  condition:
	all of them
}
