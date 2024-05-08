
rule server_address : medium {
  meta:
    description = "references a 'server address', possible C2 client"
    hash_2024_Downloads_3105 = "31054fb826b57c362cc0f0dbc8af15b22c029c6b9abeeee9ba8d752f3ee17d7d"
    hash_2023_Linux_Malware_Samples_450a = "450a7e35f13b57e15c8f4ce1fa23025a7c313931a394c40bd9f3325b981eb8a8"
    hash_2023_Linux_Malware_Samples_458e = "458e3e66eff090bc5768779d5388336c8619a744f486962f5dfbf436a524ee04"
  strings:
    $underscores = /\w{0,32}server_addr\w{0,32}/
    $mixed = /\w{0,32}serverAddr\w{0,32}/
  condition:
    any of them
}
