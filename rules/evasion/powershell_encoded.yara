
rule powershell_encoded_command_val : suspicious {
  meta:
    description = "Runs powershell with an encoded command"
    hash_2024_Downloads_4ba700b0e86da21d3dcd6b450893901c252bf817bd8792548fc8f389ee5aec78 = "fd3e21b8e2d8acf196cb63a23fc336d7078e72c2c3e168ee7851ea2bef713588"
    hash_2024_2018_04_Common_Malware_Carrier_payload = "8cdd29e28daf040965d4cad8bf3c73d00dde3f2968bab44c7d8fe482ba2057f9"
    hash_2023_grandmask_3_13_setup = "8835778f9e75e6493693fc6163477ec94aba723c091393a30d7e7b9eed4f5a54"
  strings:
    $ps = "powershell"
    $enc = /\-EncodedCommand [\w\=]{0,256}/
  condition:
    all of them
}
