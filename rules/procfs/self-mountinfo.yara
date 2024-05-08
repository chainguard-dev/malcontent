
rule proc_self_status : medium {
  meta:
    description = "gets mountinfo associated to this process"
    pledge = "stdio"
    hash_2024_Downloads_4ba700b0e86da21d3dcd6b450893901c252bf817bd8792548fc8f389ee5aec78 = "fd3e21b8e2d8acf196cb63a23fc336d7078e72c2c3e168ee7851ea2bef713588"
    hash_2023_Linux_Malware_Samples_7955 = "7955542df199c6ce4ca0bb3966dcf9cc71199c592fec38508dad58301a3298d0"
    hash_2023_Linux_Malware_Samples_df82 = "df8262a8a7208da235127a10b07fa9b87de71eb2cc9667899da60ad255a90c76"
  strings:
    $ref = "/proc/self/mountinfo" fullword
  condition:
    any of them
}
