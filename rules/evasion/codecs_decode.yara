
rule codecs_decode : high {
  meta:
    description = "decodes text with an arbitrary codec"
    hash_2023_JokerSpy_shared = "5fe1790667ee5085e73b054566d548eb4473c20cf962368dd53ba776e9642272"
    hash_2023_JokerSpy_shared = "39bbc16028fd46bf4ddad49c21439504d3f6f42cccbd30945a2d2fdb4ce393a4"
  strings:
    $val = /[\w\= ]{0,16}codecs\.decode\(\'.{0,32}\'/
  condition:
    $val
}
