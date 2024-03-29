rule chmod_executable_plus : notable {
  meta:
	description = "makes file executable"
  strings:
	$val = /chmod [\-\w ]{0,4}\+[rw]{0,2}x[ \$\@\w\/\.]{0,64}/
  condition:
	$val
}

rule chmod_executable_octal : suspicious {
  meta:
	description = "makes file executable"
  strings:
	$val = /chmod [\-\w ]{0,4}\+[rw]{0,2}[75][ \$\@\w\/\.]{0,64}/
  condition:
	$val
}

rule chmod_executable_ruby : suspicious {
  meta:
    jumpcloud = "https://www.mandiant.com/resources/blog/north-korea-supply-chain"
    hash_2023_jumpcloud_init = "d4918e0b1883e12408aba9eb26071038a45fb020f1a489a2b2a36ab8b225f673"
  strings:
    $chmod_7_val = /File\.chmod\(\d{0,16}7\d{0,16}/
  condition:
    any of them
}

