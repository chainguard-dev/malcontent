rule content_length_0: medium {
  meta:
    description                          = "Sets HTTP content length to zero"
    hash_2023_Downloads_21b3             = "21b3e304db526e2c80df1f2da2f69ab130bdad053cb6df1e05eb487a86a19b7c"
    hash_2024_Downloads_3105             = "31054fb826b57c362cc0f0dbc8af15b22c029c6b9abeeee9ba8d752f3ee17d7d"
    hash_2023_Linux_Malware_Samples_1020 = "1020ce1f18a2721b873152fd9f76503dcba5af7b0dd26d80fdb11efaf4878b1a"

  strings:
    $ref = "Content-Length: 0"

  condition:
    $ref
}
