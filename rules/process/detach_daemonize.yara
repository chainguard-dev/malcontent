
rule detach : notable {
  meta:
	description = "process detaches and daemonizes"
  strings:
	$ref = /[\w\/]{0,16}xdaemon/
	$ref2 = /[\w\/]{0,16}go-daemon/
  condition:
	any of them
}
