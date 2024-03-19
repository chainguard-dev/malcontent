rule systemd_no_output : suspicious {
  meta:
	description = "Discards all logging output"
  strings:
    $output_null = "StandardOutput=null"
    $error_null = "StandardError=null"
    $input_null = "StandardInput=null"
    $syslog = "syslog"
  condition:
    filesize < 4KB and ($output_null or $error_null) and not ($input_null or $syslog)
}
