rule bash_persist : high {
  meta:
	description = "Writes to bash configuration files"
  strings:
	$ref = ".bash_profile"
	$ref2 = ".profile"
	$ref3 = ".bashrc"
	$ref4 = ".bash_logout"
	$ref5 = "/etc/profile"
	$ref6 = "/etc/bashrc"
	$ref7 = "/etc/bash"
    $not_bash = "POSIXLY_CORRECT"
  condition:
    filesize < 2097152 and any of ($ref*) and none of ($not*)
}

rule bash_logout_persist : suspicious {
  meta:
	description = "Writes to bash configuration files to persist"
  strings:
	$ref = ".bash_logout"
    $not_bash = "POSIXLY_CORRECT"
  condition:
    filesize < 2097152 and any of ($ref*) and none of ($not*)
}

