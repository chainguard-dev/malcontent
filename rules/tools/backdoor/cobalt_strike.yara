rule cobalt_strike_indicator : suspicious {
  meta:
	description = "CobaltStrike indicator"
	author = "Florian Roth"
  strings:
	// extracted from https://github.com/Neo23x0/god-mode-rules/blob/master/godmode.yar
	$ref = "%s as %s\\%s: %d" ascii xor
  condition:
    any of them
}
