rule password_finder_mimipenguin : critical {
  meta:
	description = "Password finder/dumper, such as MimiPenguin"
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
