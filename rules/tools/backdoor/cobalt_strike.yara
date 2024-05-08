
rule cobalt_strike_indicator : suspicious {
  meta:
    description = "CobaltStrike indicator"
    author = "Florian Roth"
    hash_2024_2018_04_Common_Malware_Carrier_payload = "8cdd29e28daf040965d4cad8bf3c73d00dde3f2968bab44c7d8fe482ba2057f9"
  strings:
    $ref = "%s as %s\\%s: %d" ascii xor
  condition:
    any of them
}
