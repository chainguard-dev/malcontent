rule bidirectional_bitwise_math_php : high {
  meta:
    description = "uses bitwise math in both directions"
    ref = "https://www.reversinglabs.com/blog/python-downloader-highlights-noise-problem-in-open-source-threat-detection"
	filetypes = "php"
  strings:
	$php = "<?php"
    $x = /\-{0,1}[\da-z]{1,8} \<\< \-{0,1}\d{1,8}/
    $y = /\-{0,1}[\da-z]{1,8} \>\> \-{0,1}\d{1,8}/
  condition:
    filesize < 192KB and all of them
}

rule bitwise_obfuscation : critical {
  meta:
    description = "uses bitwise math to obfuscate code"
    ref = "https://www.reversinglabs.com/blog/python-downloader-highlights-noise-problem-in-open-source-threat-detection"
	filetypes = "php"
  strings:
	$php = "<?php"
    $bit1 = /\-{0,1}[\da-z]{1,8} \<\< \-{0,1}\d{1,8}/
    $bit2 = /\-{0,1}[\da-z]{1,8} \>\> \-{0,1}\d{1,8}/
	$f_implode = "implode("
	$f_charAt = "charAt("
	$f_substr = "substr("
	$f_ord = "ord("
  condition:
    filesize < 192KB and $php and any of ($bit*) and 3 of ($f*)
}

