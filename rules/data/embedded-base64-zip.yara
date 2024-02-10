rule base64_zip : suspicious {
    meta:
        description = "Contains base64 zip file content"
    strings:
		$header = "UEsDBB"
    condition:
        $header
}