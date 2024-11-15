rule metasploit_payload: critical {
  meta:
    description = "Metasploit shellcode (msfpayload)"

  strings:
    $msfpayload = "msfpayload"
    $metasploit = "http://www.metasploit.com"
    $payload    = "Payload: "
    $shh        = "/shh/bin"

  condition:
    2 of them
}

rule meterpreter: high windows {
  meta:
    description = "extensible payload for DLL injection and remote access"
    ref         = "https://www.offsec.com/metasploit-unleashed/about-meterpreter/"
    author      = "Florian Roth"

  strings:
    $ref = "/meterpreter/" ascii xor

  condition:
    any of them
}
