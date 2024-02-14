rule tmp_path : suspicious {
	meta:
		description = "References paths within /dev/shm (world writeable)"
	strings:
		$resolv = /\/dev\/shm\/[%\w\.\-\/]{0,64}/ 
	condition:
		any of them
}