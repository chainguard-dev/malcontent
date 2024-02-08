rule macos_signer {
  meta:
	value = "developer_id"
  strings:
	$developer_id = /Developer ID Application: (\w, \.){0,64} \(\w{0,16}\)/
	$authority = "Apple Timestamp Certification Authority"
  condition:
	all of them
}