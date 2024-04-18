rule dev_mqueue : notable {
	meta:
		description = "path reference within /dev/mqueue (world writeable)"
	strings:
		$mqueue = /\/dev\/mqueue[%\w\.\-\/]{0,64}/ 
	condition:
		any of them
}

rule dev_mqueue_hidden : suspicious {
	meta:
		description = "path reference within /dev/mqueue (world writeable)"
	strings:
		$mqueue = /\/dev\/mqueue\/\.[%\w\.\-\/]{0,64}/ 
	condition:
		any of them
}