rule dev_shm {
	meta:
		description = "references /dev/shm (world writeable)"
	strings:
		$ref = /\/dev\/shm\/[\%\w\-\/\.]{0,64}/
	condition:
		any of them
}

rule dev_shm_file : suspicious {
	meta:
		description = "reference file within /dev/shm (world writeable)"
	strings:
		// at least two characters to decrease false-positive rate
		$ref = /\/dev\/shm\/[\%\w\.]{2,64}/
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