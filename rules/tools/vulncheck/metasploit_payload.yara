rule metasploit_payload : critical {
  meta:
    hash_2012_getshell_siggen = "4863d9a15f3a1ed5dd1f84cf9883eafb6bf2b483c2c6032cfbf0d3caf3cf6dd8"
	description = "Metasploit shellcode (msfpayload)"
  strings:
    $msfpayload = "msfpayload"
    $metasploit = "http://www.metasploit.com"
    $payload = "Payload: "
    $shh = "/shh/bin"
  condition:
    2 of them
}
