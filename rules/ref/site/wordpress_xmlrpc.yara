
rule wordpress_xmlrpc : suspicious {
 meta:
	description = "References xmlrpc.php from wordpress"
  strings:
    $php_url = /[\w\/\.]{0,64}xmlrpc.php/
  condition:
	any of them
}
