rule usr_bin_path {
	meta:
		description = "path reference within /usr/bin"
	strings:
		$resolv = /\/usr\/bin\/[\w\.\-\/]{0,64}/ 
	condition:
		any of them
}