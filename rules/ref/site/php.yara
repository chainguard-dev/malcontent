
rule http_url_with_php : suspicious {
 meta:
	description = "Accesses hosted PHP files directly"
  strings:
    $php_url = /https*:\/\/[\w\.]+\/[\/\w+]\.php/
    $php_question = /[\.\w\-\/:]+\.php\?/
    $php_c = /https*:\/\/%s\/\w+.php/
    $not_bom = "BOMStorage"
    $not_path_example = " <path"
    $not_multi_path_example = "[<path"
    $not_osquery = "OSQUERY_WORKER"
    $not_brotli = "cardshillsteamsPhototruthclean"
    $not_brotli2 = "examplepersonallyindex"
    $not_manual = "manually upload"
  condition:
    any of ($php*) and none of ($not_*)
}
