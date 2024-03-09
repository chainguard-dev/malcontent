
rule node_hex_parse : suspicious {
  meta:
	description = "converts hex data to ASCII"
  strings:
	$ref = /Buffer\.from\(\w{0,16}, {0,2}'hex'\)/
  condition:
	$ref
}