rule selinux_disable_val : suspicious {
  meta:
	description = "disables SELinux security control"
  strings:
	$ref1 = "SELINUX=disabled"
	$ref2 = "setenforce 0"
  condition:
	any of them
}