rule base64_gz : suspicious {
    meta:
        description = "Contains base64 gzip content"
    strings:
		$header = "H4sI"
    condition:
        $header
}