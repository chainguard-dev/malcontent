rule sw_vers_and_libcurl: medium {
  meta:
    description                       = "fetches macOS system version and uses libcurl"
    hash_2023_Downloads_Chrome_Update = "eed1859b90b8832281786b74dc428a01dbf226ad24b182d09650c6e7895007ea"
    hash_2023_KandyKorn_kandykorn     = "927b3564c1cf884d2a05e1d7bd24362ce8563a1e9b85be776190ab7f8af192f6"

  strings:
    $sw_vers = "sw_vers" fullword
    $bin_zsh = "libcurl"

  condition:
    all of them
}


rule curl_easy_sysinfo: high {
  meta:
    description                       = "fetches macOS system information and uses curl_easy"
   strings:
	$e1 = "IOPlatformExpertDevice" fullword
	$e2 = "IOPlatformSerialNumber"
	$e3 = "ProductVersion"
	$e4 = "ProductBuildVersion"
	$curl_easy = "curl_easy"

  condition:
    all of them
}
