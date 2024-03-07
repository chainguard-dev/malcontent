
rule bash_tcp : suspicious {
	meta:
		description = "sends data via /dev/tcp (bash)"
	strings:
		$ref = /[\w \-\<]{0,32}>"{0,1}\/dev\/tcp\/[\$\{\/\:\-\w\"]{0,32}/
	condition:
		$ref
}
