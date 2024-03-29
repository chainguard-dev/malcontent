
rule indirect_python_builtins : suspicious {
  meta:
	description = "Indirectly refers to Python builtins"
  strings:
	$val = /getattr\(__builtins__,[ \w\.\)\)]{0,64}/
condition:
	any of them
}
