rule ruby_eval_base64_decode : critical {
  meta:
	description = "Evaluates base64 content"
  strings:
    $eval_base64_decode = "eval(Base64."
  condition:
    any of them
}