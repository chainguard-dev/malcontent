rule tmp_path : suspicious {
	meta:
		description = "References paths within /dev/mqueue (world writeable)"
	strings:
		$resolv = /\/dev\/mqueue[%\w\.\-\/]{0,64}/ 
	condition:
		any of them
}