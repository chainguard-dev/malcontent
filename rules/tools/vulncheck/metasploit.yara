
rule metasploit_payload : critical {
  meta:
    description = "Metasploit shellcode (msfpayload)"
    hash_2013_GetShell = "4863d9a15f3a1ed5dd1f84cf9883eafb6bf2b483c2c6032cfbf0d3caf3cf6dd8"
  strings:
    $msfpayload = "msfpayload"
    $metasploit = "http://www.metasploit.com"
    $payload = "Payload: "
    $shh = "/shh/bin"
  condition:
    2 of them
}

rule meterpreter : high windows {
  meta:
    description = "extensible payload for DLL injection and remote access"
    ref = "https://www.offsec.com/metasploit-unleashed/about-meterpreter/"
    author = "Florian Roth"
  strings:
    $ref = "/meterpreter/" ascii xor
  condition:
    any of them
}
