rule cipher_exfil : high {
  meta:
    description = "may exfiltrate base64-encoded zlib content"
	ref = "https://checkmarx.com/blog/crypto-stealing-code-lurking-in-python-package-dependencies/"
	filetypes = "py"
  strings:
	$s_zlib = "zlib" fullword
	$s_compress = "compress" fullword
	$s_b64encode = "b64encode"
	$s_json = "json" fullword
	$s_dumps = "dumps" fullword
	$s_map_chr = "chr" fullword

	$http = "http.client"
	$h_requests = "requests"
  condition:
    filesize < 8KB and all of ($s*) and any of ($h*)
}

rule cipher_exfil2 : high {
  meta:
    description = "may exfiltrate base64-encoded zlib content"
	ref = "https://checkmarx.com/blog/crypto-stealing-code-lurking-in-python-package-dependencies/"
	filetypes = "py"
  strings:
	$s_zlib = "zlib" fullword
	$s_compress = "compress" fullword
	$s_b64encode = "b64encode"
	$s_b64decode = "b64decode"
	$s_json = "json" fullword
	$s_dumps = "dumps" fullword
	$s_map_chr = "chr" fullword
	$s_getlogin = "getlogin" fullword
	$s_decode = "decode" fullword

	$http = "http"
	$h_requests = "requests"
  condition:
    filesize < 8KB and 85% of ($s*) and any of ($h*)
}
