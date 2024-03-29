rule server_address : notable {
	meta:
		description = "references a 'server address', possible C2 client"
	strings:
		$underscores = /\w{0,32}server_addr\w{0,32}/
		$mixed = /\w{0,32}serverAddr\w{0,32}/
	condition:
		any of them
}