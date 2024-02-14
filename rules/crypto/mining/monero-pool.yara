rule monero_pool : suspicious {
	meta:
		description = "References Monero mining pools"
	strings:
		$ref = "monero"
		$ref2 = "pool"
	condition:
		all of them
}



