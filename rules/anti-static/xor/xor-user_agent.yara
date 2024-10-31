
rule xor_mozilla : critical {
  meta:
    description = "XOR'ed user agent, often found in backdoors"
    author = "Florian Roth"
    hash_2023_Tiganie_S3npai_29ae = "29ae9389dcb1f5b0bc3a52543b3ddfc933a65c4943709907fd136decf717255c"
    hash_2023_Unix_Dropper_Mirai_1550 = "1550ae8e301f86778bb9a2aa91df606f61edc51273ab61053817b8322af71afc"
    hash_2023_Unix_Dropper_Mirai_2d11 = "2d115b7bb43411fe88ba4cb929843b5dcf897559a6c9d2ec80554723604ea4e2"
  strings:
    $Mozilla_5_0 = "Mozilla/5.0" ascii wide xor(1-255)
  condition:
    any of them
}
