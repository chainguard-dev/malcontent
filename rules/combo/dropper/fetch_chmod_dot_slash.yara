rule curl_chmod_relative_run : suspicious{
  meta:
	description = "fetches file, makes it executable, runs it"
  strings:
	$chmcurlod = /curl [\-\w \$\@\{\w\/\.\:]{0,96}/
	$chmod = /chmod [\-\w \$\@\{\w\/\.]{0,64}/
	$dot_slah = /\.\/[a-z]{1,2}[a-z\.\/\- ]{0,32}/ fullword
  condition:
	all of them
}

rule wget_chmod_relative_run : suspicious{
  meta:
	description = "fetches file, makes it executable, runs it"
  strings:
	$chmcurlod = /wget [\-\w \$\@\{\w\/\.\:]{0,96}/
	$chmod = /chmod [\-\w \$\@\{\w\/\.]{0,64}/
	$dot_slah = /\.\/[a-z]{1,2}[a-z\.\/\- ]{0,32}/ fullword
  condition:
	all of them
}
