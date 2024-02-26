rule selinux_disable : suspicious {
  strings:
	$ref1 = "SELINUX=disabled"
	$ref2 = "setenforce 0"
  condition:
	any of them
}