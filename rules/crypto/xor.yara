rule xor_decode_encode : suspicious {
	meta:
		description = "decodes/encodes XOR content"
	strings:
		$decode = /\w{0,16}XorDecode[\w]{0,32}/
		$encode = /\w{0,16}XorEncode[\w]{0,32}/
		$file = /\w{0,16}XorFile[\w]{0,32}/

		$decode_ = /\w{0,16}xor_decode[\w]{0,32}/
		$encode_ = /\w{0,16}xor_encode[\w]{0,32}/
		$file_ = /\w{0,16}xor_file[\w]{0,32}/
	condition:
		any of them
}
