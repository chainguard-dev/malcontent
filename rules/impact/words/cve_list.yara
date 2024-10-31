
rule cve_list : medium {
  meta:
    description = "references a 'CVE List'"
    hash_2024_Chaos_1d36 = "1d36f4bebd21a01c12fde522defee4c6b4d3d574c825ecc20a2b7a8baa122819"
    hash_2024_Chaos_1fc4 = "1fc412b47b736f8405992e3744690b58ec4d611c550a1b4f92f08dfdad5f7a30"
    hash_2024_Chaos_27cd = "27cdb8d8f64ce395795fdbde10cf3a08e7b217c92b7af89cde22abbf951b9e99"
  strings:
    $ref = /[a-zA-Z\-_ ]{0,16}cveList[a-zA-Z\-_ ]{0,16}/ fullword
    $ref2 = /[a-zA-Z\-_ ]{0,16}cve_list[a-zA-Z\-_ ]{0,16}/ fullword
  condition:
    any of them
}
