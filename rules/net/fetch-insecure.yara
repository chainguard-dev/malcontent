rule curl_insecure_val : notable {
	meta:
		description = "Invokes curl in insecure mode"
	strings:
		$ref = /curl[\w\- ]{0,5}-k[ \-\w:\/]{0,64}/
		$ref2 = /curl[\w\- ]{0,5}--insecure[ \-\w:\/]{0,64}/
	    $c_wget_insecure = /wget[\w\- ]{0,5}--no-check-certificate[\/\- \w\%\(\{\}\'\"\)\$]{0,128}/
	condition:
		any of them
}
