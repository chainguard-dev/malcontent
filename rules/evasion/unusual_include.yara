rule php_suppressed_include : high {
  meta:
    description = "Includes a file, suppressing errors"
	credit = "Inspired by DodgyPHP rule in php-malware-finder"
  strings:
	$php = "<?php"
	$include = /@\s*include\s*/
 condition:
	filesize < 5MB and all of them
}
