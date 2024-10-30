rule obfuscated_bypass_amsi: windows high {
  meta:
    description = "bypass AMSI (Anti-Malware Scan Interface)"
    author      = "Florian Roth"
    ref         = "https://gustavshen.medium.com/bypass-amsi-on-windows-11-75d231b2cac6"

  strings:
    // extracted from https://github.com/Neo23x0/god-mode-rules/blob/master/godmode.yar
    $amsi_base64 = "AmsiScanBuffer" ascii wide base64
    $amsi_xor    = "AmsiScanBuffer" xor(0x01-0xff)

  condition:
    any of them
}
