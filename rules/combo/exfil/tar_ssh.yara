
rule tar_ssh_net : notable {
  strings:
	$s_curl = "curl" fullword
	$s_wget = "wget" fullword
	$s_socket = "socket" fullword

	$h = ".ssh" fullword

	$z_zip = "zip" fullword
	$z_tar = "tar" fullword
  condition:
	$h and any of ($s*) and any of ($z*)
}