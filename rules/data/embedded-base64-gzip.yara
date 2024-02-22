rule base64_gz : notable {
    meta:
        description = "Contains base64 gzip content"
    strings:
		$header = "H4sIA"
    condition:
        $header
}