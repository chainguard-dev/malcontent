
rule target_ip : notable {
  meta:
    description = "References a target IP"
    hash_2023_Linux_Malware_Samples_123e = "123e6d1138bfd58de1173818d82b504ef928d5a3be7756dd627c594de4aad096"
    hash_2023_Linux_Malware_Samples_4fc4 = "4fc458c46bc0b15f8c7e73d1979ad844e97072f4b1b7ad7fc9c8ca1e211ef98b"
    hash_2023_Linux_Malware_Samples_514c = "514cf58af53eca0f8aeb7c2567b40b03804a70804170baca08176d404baaf587"
  strings:
    $ref = "target ip"
    $ref2 = "TargetIP"
    $ref3 = "target_ip"
    $ref4 = "target IP"
  condition:
    any of them
}
