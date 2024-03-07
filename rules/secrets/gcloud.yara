rule gcloud_config : notable {
	meta:
		description = "Access gcloud configuration files"
	strings:
		$ref = ".config/gcloud"
		$ref2 = "application_default_credentials.json"
	condition:
		any of them
}
