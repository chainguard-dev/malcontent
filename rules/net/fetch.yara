
rule curl : notable {
	meta:
		description = "Invokes curl"
	strings:
		$ref = /curl [\w\- :\"\/]{0,64}-o[\w\- :\"\/]{0,64}/
	condition:
		$ref
}

rule curl_download : notable {
	meta:
		description = "Invokes curl to download a file"
	strings:
		$ref = /curl [\w\- :\"\/]{0,64}-[oO][\w\- :\"\/]{0,64}/
	condition:
		$ref
}

rule curl_agent : suspicious {
	meta:
		description = "Invokes curl with a custom user agent"
	strings:
		$ref = /curl [\w\- :\"\/]{0,64}-a[ "][\w\- :\"\/]{0,64}/
	condition:
		$ref
}
