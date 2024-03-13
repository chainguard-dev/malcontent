rule usr_local_path : notable {
	meta:
		description = "references paths within /usr/local"
	strings:
		$val = /\/usr\/local\/[\w\.\-\/]{0,64}/ 
		$go = "/usr/local/go"
	condition:
		$val and not $go
}