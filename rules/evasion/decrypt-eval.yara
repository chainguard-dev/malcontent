import "math"

rule python_exec_near_enough_decrypt : critical {
  meta:
	description = "Evaluates code from encrypted content"
  strings:
    $exec = "exec("
	$decrypt = "decrypt("
  condition:
	all of them and math.abs(@decrypt - @exec) <= 256
}

rule python_exec_near_enough_fernet : critical {
  meta:
	description = "Evaluates code from encrypted content"
  strings:
    $exec = "exec("
	$fernet = "Fernet"
  condition:
	all of them and math.abs(@fernet - @exec) <= 256
}