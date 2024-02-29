
rule http_url_with_php : notable {
 meta:
	description = "Accesses hosted PHP files directly"
  strings:
    $php_url = /https*:\/\/[\w\.]{0,160}\/[\/\w\_\-]{0,160}\.php/
    $php_question = /[\.\w\-\_\/:]{0,160}\.php\?/
    $php_c = /https*:\/\/%s\/[\w\/\-\_]{0,160}.php/
    $not_bom = "BOMStorage"
    $not_path_example = " <path"
    $not_multi_path_example = "[<path"
    $not_osquery = "OSQUERY_WORKER"
    $not_brotli = "cardshillsteamsPhototruthclean"
    $not_brotli2 = "examplepersonallyindex"
    $not_manual = "manually upload"
	$not_ecma = "http://wiki.ecmascript.org"
  condition:
    any of ($php*) and none of ($not_*)
}
