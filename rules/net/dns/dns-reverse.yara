
rule in_addr_arpa : medium {
  meta:
    pledge = "inet"
    description = "looks up the reverse hostname for an IP"
    hash_2024_Downloads_3105 = "31054fb826b57c362cc0f0dbc8af15b22c029c6b9abeeee9ba8d752f3ee17d7d"
    hash_2024_Downloads_a031 = "a031da66c6f6cd07343d5bc99cc283528a5b7f04f97b2c33c2226a388411ec61"
    hash_2024_Downloads_e241 = "e241a3808e1f8c4811759e1761e2fb31ce46ad1e412d65bb1ad9e697432bd4bd"
  strings:
    $ref = ".in-addr.arpa"
    $ref2 = "ip6.arpa"
  condition:
    any of them
}
