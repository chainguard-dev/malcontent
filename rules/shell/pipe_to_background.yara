rule pipe_to_bg : notable {
  meta:
  	description = "pipes to backgrounded shell"
  strings:
    $ref = "| sh &"
  condition:
	$ref
}
