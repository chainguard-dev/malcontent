rule base64_shell_decode : notable {
  meta:
	description = "calls base64 command to decode strings"
  strings:
    $base64_d = "base64 -d"
    $base64_d_b64 = "base64 -d" base64
    $base64_D = "base64 -D"
    $base64_D_b64 = "base64 -D" base64
    $base64_decode = "base64 --decode"
    $base64_decode_b64 = "base64 --decode" base64
    $base64_re = /base64 [\w\%\@\- ]{0,16} -[dD]/

	$not_example = "base64 --decode | keybase"
  condition:
    any of ($base64*) and none of ($not*)
}
