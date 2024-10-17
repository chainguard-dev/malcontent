rule join_map_chr : high {
  meta:
    description = "assembles strings from character code constants"
	ref = "https://checkmarx.com/blog/crypto-stealing-code-lurking-in-python-package-dependencies/"
	filetypes = "py"
  strings:
	$ref = /join\(map\(chr,\[\d{1,3},\d{1,3},[\d\,]{1,32}/
  condition:
    filesize < 8KB and $ref
}
