rule libc {
  strings:
	$signal = "_signal" fullword
	$sigaction = "sigaction" fullword
  condition:
	any of them
}