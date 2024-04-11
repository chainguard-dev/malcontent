rule password_finder_mimipenguin : critical {
  meta:
	description = "Password finder/dumper, such as MimiPenguin"
  strings:
	$lightdm = "lightdm" fullword
	$apache2 = "apache2.conf" fullword
	$vsftpd = "vsftpd" fullword
	$shadow = "/etc/shadow"
	$gnome = "gnome-keyring-daemon"
	$password = "password"
	$finder = "Finder"
	$sshd_config = "sshd_config" fullword
  condition:
	5 of them
}
