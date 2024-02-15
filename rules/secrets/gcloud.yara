rule gcloud_config : notable {
	meta:
		description = "Access gcloud configuration files"
	strings:
		$ref = ".config/gcloud"
	condition:
		any of them
}
