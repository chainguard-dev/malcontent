rule pam_passwords : suspicious {
  meta:
	description = "password authentication module may record passwords"
  strings:
	$auth = "pam_authenticate"
	$pass = "password"
	
	$f_open = "open"
	$f_fopen = "fopen"
	$f_socket = "socket"
	$f_exfil = "exfil"
  condition:
	$auth and $pass and any of ($f*)
}