rule dev_shm : suspiciuos {
	meta:
		description = "path reference within /dev/shm (world writeable)"
	strings:
		$ref = /\/dev\/shm\/[%\w\.\-\/]{0,64}/ 
	condition:
		any of them
}

rule dev_shm_sh : critical {
	meta:
		description = "References shell script within /dev/shm (world writeable)"
	strings:
		$ref = /\/dev\/shm\/[%\w\.\-\/]{0,64}\.sh/ 
	condition:
		any of them
}


rule dev_shm_hidden : critical {
	meta:
		description = "path reference within /dev/shm (world writeable)"
	strings:
		$dev_shm = /\/dev\/shm\/\.[%\w\.\-\/]{0,64}/ 
	condition:
		any of them
}