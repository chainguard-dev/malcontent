rule wifi {
	meta:
		description = "Wireless networking"
	strings:
		$ref = "BSSID"
		$ref2 = "bssid"
		$ref3 = "wps_supplicant"
		$ref4 = "wpa_supplicant"
	condition:
		any of them
}
