import "math"

rule python_popen_near_enough: critical {
  meta:
	description = "runs programs based on base64 content"
  strings:
    $popen = "os.popen("
	$base64 = "b64decode"
  condition:
	  all of them and math.abs(@base64 - @popen) < 128
}
