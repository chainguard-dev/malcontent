rule bash_persist : notable {
  meta:
	description = "access bash startup files"
  strings:
	$ref = ".bash_profile"
	$ref2 = ".profile" fullword
	$ref3 = ".bashrc" fullword
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

