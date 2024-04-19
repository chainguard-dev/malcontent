rule xor_mozilla : critical {
  meta:
	description = "XOR'ed user agent, often found in backdoors"
	author = "Florian Roth"
  strings:
	// extracted from https://github.com/Neo23x0/god-mode-rules/blob/master/godmode.yar
	$Mozilla_5_0 = "Mozilla/5.0" xor(0x01-0xff) ascii wide
  condition:
    any of them
}
