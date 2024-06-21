rule php_non_printable : medium {
  meta:
	description = "non-printable values unexpectedly passed to a function"
	credit = "Ported from https://github.com/jvoisin/php-malware-finder"
  strings:
    $ref = /(function|return|base64_decode).{,64}[^\x09-\x0d\x20-\x7E]{3}/
    $php = "<?php"
  condition:
	filesize < 5MB and all of them
}
