
rule upload : notable {
	meta:
		description = "Uploads files"
	strings:
		$ref = "upload" fullword
		$ref2 = "UPLOAD" fullword
		$ref3 = "Upload" fullword
	condition:
		any of them
}

rule curl_upload_command : suspicious {
  meta:
	description = "Uses curl to upload data"
  strings:
    $curl_upload = "url --upload-file"
    $kinda_curl_inesecure_data = "--insecure --data"
    $kinda_curl_k_data = "-k --data"
    $kinda_curl_k_d = "-k -d"
  condition:
    any of them
}