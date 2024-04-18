
rule codecs_decode : suspicious {
  meta:
	description = "decodes text with an arbitrary codec"
  strings:
	$val = /[\w\= ]{0,16}codecs\.decode\(\'.{0,32}\'/
  condition:
	$val
}