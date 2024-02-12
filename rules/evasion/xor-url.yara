
rule xor_url : suspicious {
	meta:
		description = "URL hidden using XOR encryption"
	strings:
		$http = "http:" xor(1-255)
		$https = "https:" xor(1-255)
		$ftp = "ftp:/" xor(1-255)
		$office = "office" xor(1-255)
		$google = "google" xor(1-255)
		$microsoft = "microsoft" xor(1-255)
		$apple = "apple" xor(1-255)
		$dot_com_slash = ".com/" xor(1-255)
	//	$dot_com_slash = "/api/" xor(1-255)
		$user_agent = "User-Agent" xor(1-255)
	condition:
		any of them
}
