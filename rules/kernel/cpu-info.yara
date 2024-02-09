
rule host_processor_info {
	meta:
		syscall = "host_processor_info"
		description = "returns hardware processor, count"
		ref = "https://developer.apple.com/documentation/kernel/1502854-host_processor_info"
	strings:
		$ref = "host_processor_info"
	condition:
		any of them
}


rule host_processors {
	meta:
		syscall = "host_processors"
		description = "returns hardware processor, count"
		ref = "https://developer.apple.com/documentation/kernel/1502854-host_processor_info"
	strings:
		$ref = "host_processors"
	condition:
		any of them
}
