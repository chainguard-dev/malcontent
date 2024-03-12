rule password_finder_mimipenguin : critical {
  meta:
	description = "Password finder/dumper, such as MimiPengiuin"
  strings:
	$lightdm = "lightdm" fullword
	$apache2 = "apache2"
	$vsftpd = "vsftpd"
	$shadow = "/etc/shadow"
	$gnome = "gnome-keyring-daemon"
	$password = "password"
	$finder = "Finder"
	$ssh = "ssh"
  condition:
	5 of them
}

rule password_finder_generic : suspicious {
  meta:
	description = "password finder or dumper"
  strings:
	$ref = "findPassword"
	$ref2 = "find_password"
  condition:
	any of them
}

rule password_dumper_generic : suspicious {
  meta:
	description = "password dumper"
  strings:
	$ref3 = "dumpPassword"
	$ref4 = "dump_password"
  condition:
	any of them
}
