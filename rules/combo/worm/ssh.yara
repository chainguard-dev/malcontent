rule ssh_snake_worm : suspicious {
  meta:
	description = "possible SSH worm like SSH-Snake"
  strings:
	$s_dot_ssh = ".ssh"
	$s_authorized_keys = "authorized_keys"

	$h_etc_hosts = "/etc/hosts"
	$h_getent = "getent ahostsv4"

	$u_base64 = "base64"
	$u_uname = "uname"

	$strict_host = "StrictHostKeyChecking"
  condition:
	$strict_host and all of ($s*) and any of ($h*) and any of ($u*)
}

rule ssh_worm_router : suspicious {
  meta:
	description = "ssh worm targetting routers"
  strings:
	$s_dot_ssh = ".ssh"

	$h_etc_hosts = "/etc/hosts"

    $p_root123 = "root123"
    $p_passw0rd = "Passw0rd"
    $p_admin123 = "admin123"
    $p_Admin123 = "Admin123"
	$p_qwerty123 = "qwerty123"
  condition:
	all of ($s*) and any of ($h*) and any of ($p*)
}
