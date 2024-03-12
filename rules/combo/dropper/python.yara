
rule python_eval_or_exec : critical {
  strings:
    $exec_requests = "exec(requests.get"
    $eval_requests = "eval(requests.get"
  condition:
    filesize < 16384 and any of them
}


rule http_open_write_system : suspicious {
  strings:
	$http = "http"
	$h_rget = "requests.get"

	$open = "open("

	$write = "write("

	$system = "os.system("
	$sys_popen = "os.popen"
  condition:
    filesize < 16384 and any of ($h*) and $open and $write and any of ($sys*)
}
