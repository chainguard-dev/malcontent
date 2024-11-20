rule base64_content: medium {
  meta:
    description = "Contains embedded base64 content"

  strings:
	$b64_st = /\"\w{6,2048}==\"/

  condition:
    any of them
}
