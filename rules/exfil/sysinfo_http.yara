
rule sysinfo_http : suspicious {
  meta:
	description = "sends host information via HTTP GET variables"
  strings:
	$ref = "&hostname="
	$ref2 = "&uname="
  condition:
	any of them
}
