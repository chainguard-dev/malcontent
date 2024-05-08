import "math"

rule remote_eval : critical {
  meta:
    description = "Evaluates remotely sourced code"
    hash_2019_restclient_request = "ba46608e52a24b7583774ba259cf997c6f654a398686028aad56855a2b9d6757"
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
    hash_2019_active_controller_middleware = "9a85e7aee672b1258b3d4606f700497d351dd1e1117ceb0e818bfea7922b9a96"
    hash_2023_1_1_6_payload = "cbe882505708c72bc468264af4ef5ae5de1b75de1f83bba4073f91568d9d20a1"
    hash_2023_0_0_7_payload = "bb6ca6bfd157c39f4ec27589499d3baaa9d1b570e622722cb9bddfff25127ac9"
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
