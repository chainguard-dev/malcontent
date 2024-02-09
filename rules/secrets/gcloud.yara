rule gcloud : suspicious {
	meta:
		description = "Access gcloud configuration files"
	strings:
		$ref = ".config/gcloud"
	condition:
		any of them
}
