rule proc_self_status: medium {
  meta:
    description = "gets status associated to this process, including capabilities"
    pledge      = "stdio"

    hash_2023_Linux_Malware_Samples_7955 = "7955542df199c6ce4ca0bb3966dcf9cc71199c592fec38508dad58301a3298d0"
    hash_2023_Linux_Malware_Samples_df82 = "df8262a8a7208da235127a10b07fa9b87de71eb2cc9667899da60ad255a90c76"

  strings:
    $ref = "/proc/self/status" fullword

  condition:
    any of them
}
