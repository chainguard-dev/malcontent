rule powershell_encoded_command_val: high windows {
  meta:
    description = "Runs powershell with an encoded command"

    hash_2024_2018_04_Common_Malware_Carrier_payload = "8cdd29e28daf040965d4cad8bf3c73d00dde3f2968bab44c7d8fe482ba2057f9"
    hash_2023_grandmask_3_13_setup                   = "8835778f9e75e6493693fc6163477ec94aba723c091393a30d7e7b9eed4f5a54"

  strings:
    $ps  = "powershell"
    $enc = /\-EncodedCommand [\w\=]{0,256}/

  condition:
    all of them
}
