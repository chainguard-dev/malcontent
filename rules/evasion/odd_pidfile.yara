rule exotic_pid_file : suspicious {
	meta:
		description = "unusual pid (process id) file location"
	strings:
		$users = /\/Users\/[%\w\.\-\/]{0,64}\.pid/
		$tmp = /\/tmp\/[%\w\.\-\/]{0,64}\.pid/
		$hidden = /[\w\/]{0,32}\/\.[\%\w\.\-\/]{0.16}\.pid/
	condition:
		any of them
}