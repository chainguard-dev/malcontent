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