
rule upload : notable {
	meta:
		description = "uploads files"
	strings:
		$ref = /upload\w{0,16}/
		$ref2 = /UPLOAD\w{0,16}/
		$ref3 = /Upload\w{0,16}/
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