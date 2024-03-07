
rule detach : suspicious {
  meta:
	description = "process detaches and daemonizes"
  strings:
	$ref = "xdaemon"
	$ref2 = "go-daemon"
  condition:
	any of them
}
