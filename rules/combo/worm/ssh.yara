rule generic_scan_tool : critical {
  meta:
	description = "Probably an SSH worm, like SSH-Snake"
  strings:
	$s_dot_ssh = ".ssh"
	$s_authorized_keys = "authorized_keys"

	$h_etc_hosts = "/etc/hosts"
	$h_getent = "getent ahostsv4"

	$u_base64 = "base64"
	$u_uname = "uname"
  condition:
	all of ($s*) and any of ($h*) and any of ($u*)
}
