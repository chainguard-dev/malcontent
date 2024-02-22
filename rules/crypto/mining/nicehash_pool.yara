rule nicehash_pool : suspicious {
	meta:
		description = "References Nicehash and mining pools"
	strings:
		$ref = "nicehash"
		$ref2 = "pool"
	condition:
		all of them
}



