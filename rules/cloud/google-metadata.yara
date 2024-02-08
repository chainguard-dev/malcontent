rule google_metadata {
	strings:
		$ref = "Metadata-Flavor"
	condition:
		any of them
}



