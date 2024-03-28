import "math"

rule remote_eval : critical {
  meta:
	description = "Evaluates remotely sourced code"
  strings:
	$http = "http"
    $eval_open_ruby = /eval\(open[\(\)\"\'\-\w:\/\.]{0,32}/
    $exec_requests = /exec\(requests\.get[\(\)\"\'\-\w:\/\.]{0,32}/
    $eval_requests = /eval\(requests\.get[\(\)\"\'\-\w:\/\.]{0,32}/
  condition:
    filesize < 65535 and $http and any of ($e*)
}

rule remote_eval_close : critical {
  meta:
	description = "Evaluates remotely sourced code"
  strings:
	$eval = "eval("
	$header = /(GET|POST|COOKIE|cookie)/
  condition:
	math.max(@header, @eval) - math.min(@header, @eval) < 96
}

rule python_exec_near_requests : critical {
  meta:
	description = "Evaluates code from encrypted content"
  strings:
	$exec = "exec("
	$requests = "equests.get("
  condition:
	all of them and math.abs(@requests - @exec) <= 128
}

rule python_eval_near_requests : critical {
  meta:
	description = "Evaluates code from encrypted content"
  strings:
	$eval = "eval("
	$requests = "equests.get("
  condition:
	all of them and math.abs(@requests - @eval) <= 128
}