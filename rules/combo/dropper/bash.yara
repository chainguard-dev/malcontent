rule fetch_chmod_run_oneliner_value : critical {
	meta:
		description = "fetches, chmods, and runs a program"
	strings:
		$ref = /[a-z](url|get) .{4,64}chmod .{4,64}\.\/[a-z]{1,16}/
	condition:
		any of them
}

rule curl_chmod_relative_run : notable {
  meta:
	description = "may fetch file, make it executable, and run it"
  strings:
	$chmcurlod = /curl [\-\w \$\@\{\w\/\.\:]{0,96}/
	$chmod = /chmod [\-\w \$\@\{\w\/\.]{0,64}/
	$dot_slah = /\.\/[a-z]{1,2}[a-z\.\/\- ]{0,32}/ fullword
  condition:
	all of them
}

rule wget_chmod_relative_run : notable {
  meta:
	description = "may fetch file, make it executable, and run it"
  strings:
	$chmcurlod = /wget [\-\w \$\@\{\w\/\.\:]{0,96}/
	$chmod = /chmod [\-\w \$\@\{\w\/\.]{0,64}/
	$dot_slah = /\.\/[a-z]{1,2}[a-z\.\/\- ]{0,32}/ fullword
  condition:
	all of them
}

rule dev_null_rm : notable {
  strings:
    $dev_null_rm = /[ \w\.\/\&\-%]{0,32}\/dev\/null\;rm[ \w\/\&\.\-\%]{0,32}/
  condition:
    any of them
}

rule sleep_rm : notable {
  strings:
    $dev_null_rm = /sleep;rm[ \w\/\&\.\-\%]{0,32}/
  condition:
    any of them
}


rule nohup_bash_background : suspicious {
  strings:
	$ref = /nohup bash [\%\w\/\>]{0,64} &/
  condition:
    any of them
}


