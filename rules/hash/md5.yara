
rule MD5 {
  meta:
    description = "Uses the MD5 signature format"
  strings:
    $ref = /MD5_[\w\:]{0,16}/
    $ref2 = /md5:[\w\:]{0,16}/
  condition:
    any of them
}

rule md5_verify : notable {
  meta:
    description = "Verifies MD5 signatures"
    hash_2024_Downloads_4b97 = "4b973335755bd8d48f34081b6d1bea9ed18ac1f68879d4b0a9211bbab8fa5ff4"
    hash_2021_CDDS_UserAgent_v2019 = "9b71fad3280cf36501fe110e022845b29c1fb1343d5250769eada7c36bc45f70"
    hash_2021_CDDS_UserAgent_v2021 = "d599d7814adbab0f1442f5a10074e00f3a776ce183ea924abcd6154f0d068bb4"
  strings:
    $ref = "md5 expect"
    $ref2 = "md5 mismatch"
    $ref3 = "FileMd5"
    $ref4 = "FileMD5"
  condition:
    any of them
}
