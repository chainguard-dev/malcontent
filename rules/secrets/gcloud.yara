rule gcloud {
	strings:
		$ref = ".config/gcloud"
	condition:
		any of them
}
