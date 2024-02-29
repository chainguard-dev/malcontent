
rule python_eval_or_exec {
  strings:
    $exec_requests = "exec(requests.get"
    $eval_requests = "eval(requests.get"
  condition:
    filesize < 1048576 and any of them
}
