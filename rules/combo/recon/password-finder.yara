rule password_finder : critical {
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
