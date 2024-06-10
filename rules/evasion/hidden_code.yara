rule php_image_include : critical {
  meta:
    description = "Includes PHP code from within a image file"
	credit = "Inspired by DodgyPHP rule in php-malware-finder"
  strings:
	$php = "<?php"
    $include = /include\s*\(\s*[^\.]+\.(png|jpg|gif|bmp)/
 condition:
	filesize < 5MB and all of them
}

rule php_in_image : critical {
  meta:
    description = "Image file contains PHP code"
	credit = "Inspired by DodgyPHP rule in php-malware-finder"
  strings:
	$gif = {47 49 46 38 ?? 61} // GIF8[version]a
	$png = {89 50 4E 47 0D 0a 1a 0a} // \X89png\X0D\X0A\X1A\X0A
	$jpeg = {FF D8 FF E0 ?? ?? 4A 46 49 46 } // https://raw.githubusercontent.com/corkami/pics/master/JPG.png

	$php = "<?php"
  condition:
        ($gif at 0 or $png at 0 or $jpeg at 0) and $php
}
