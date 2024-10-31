
rule run_sleep_delete : critical {
  meta:
    description = "run executable, sleep, and delete"
    hash_2024_Downloads_4ba700b0e86da21d3dcd6b450893901c252bf817bd8792548fc8f389ee5aec78 = "fd3e21b8e2d8acf196cb63a23fc336d7078e72c2c3e168ee7851ea2bef713588"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2023_Linux_Malware_Samples_df3b = "df3b41b28d5e7679cddb68f92ec98bce090af0b24484b4636d7d84f579658c52"
  strings:
    $chmod = /chmod [\-\+\w \$\@\{\w\/\.]{0,64}/
    $dot_slash = /\.\/[a-z]{1,2}[a-z\.\/\- ]{0,32}/ fullword
	$sleep = /sleep \d{1,2}/ fullword
	$rm = /rm \.\/[a-z]{1,2}[a-z\.\/\- ]{0,32}/ fullword
  condition:
    filesize < 64KB and all of them
}

rule fetch_run_sleep_delete : critical {
  meta:
    description = "fetch, run executable, sleep, and delete"
  strings:
    $url = /https*:\/\/[\w][\w\.\/\-_\?=\@]{8,64}/
	$sleep = /sleep \d{1,2}/ fullword
	$rm = /rm [\-\w ]{0,4}f[ \$\w\/\.]{0,32}/
	$path_tmp = "/tmp"
	$path_var = "/var/"
	$path_dev_shm = "/dev/shm"
	$run_quoted = /\"\$[\-\w\/\$]{1,12}\"/ fullword
	$run_dot_slash = /\.\/[\-\w\$]{1,12}/ fullword
  condition:
    filesize < 1KB and $url and $sleep and $rm and any of ($path*) and any of ($run*)
}

