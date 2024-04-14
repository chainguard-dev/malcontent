rule chromium_master_password : suspicious {
	meta:
		description = "Gets Chromium credit card information"
	strings:
		$web_data = "Web Data"
		$encrypted_key = "credit_cards"
		$c = "Chrome"
		$c2 = "Chromium"
	condition:
		any of ($c*) and $web_data and $encrypted_key
}
