
rule xor_table {
  meta:
	description = "Contains a table that may be used for XOR decryption"
  strings:
	$ref = "56789abcdefghijklmnopqrstuvwxyzABCDE"
  condition:
    any of them
}