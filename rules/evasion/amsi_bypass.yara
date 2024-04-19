rule obfuscated_bypass_amsi : windows suspicious {
  meta:
	description = "bypass AMSI (Anti-Malware Scan Interface)"
	author = "Florian Roth"
  strings:
	// extracted from https://github.com/Neo23x0/god-mode-rules/blob/master/godmode.yar
    $amsi_base64 = "AmsiScanBuffer" ascii wide base64
    $amsi_xor = "AmsiScanBuffer" xor(0x01-0xff)
  condition:
	any of them
}
