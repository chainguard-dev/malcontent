
rule javascript_dropper : critical {
  meta:
    description = "Javascript dropper"
  strings:
	$lib_http = /require\(['"]https{0,1}['"]\);/
	$lib_fs = /require\(['"]fs['"]\);/
	$lib_child_process = /require\(['"]child_process['"]\);/
	$http = "http://"
	$https = "https://"
	$temp = "TEMP"
	$other_unlink = ".unlink"
	$other_create = ".createWriteStream"
	$other_http = "http.get"
  condition:
    filesize < 2KB and all of ($lib*) and $temp and any of ($http*) and 2 of ($other*)
}
