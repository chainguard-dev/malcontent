rule common_username_block_list: high {
  meta:
    description = "avoids execution if user has a particular name"
    ref         = "https://www.zscaler.com/blogs/security-research/technical-analysis-bandit-stealer"

  strings:
    $ = "3u2v9m8" fullword
    $ = "8Nl0ColNQ5bq" fullword
    $ = "8VizSM" fullword
    $ = "Abby" fullword
    $ = "BvJChRPnsxn" fullword
    $ = "Frank" fullword
    $ = "HEUeRzl" fullword
    $ = "Harry Johnson" fullword
    $ = "John" fullword
    $ = "Julia" fullword
    $ = "Lisa" fullword
    $ = "Louise" fullword
    $ = "Lucas" fullword
    $ = "PateX" fullword
    $ = "PqONjHVwexsS" fullword
    $ = "PxmdUOpVyx" fullword
    $ = "RDhJ0CNFevzX" fullword
    $ = "RGzcBUyrznReg" fullword
    $ = "SqgFOf3G" fullword
    $ = "User01" fullword
    $ = "WDAGUtilityAccount" fullword
    $ = "fred" fullword
    $ = "george" fullword
    $ = "h7dk1xPr" fullword
    $ = "hmarc" fullword
    $ = "kEecfMwgj" fullword
    $ = "lmVwjj9b" fullword
    $ = "mike" fullword
    $ = "patex" fullword
    $ = "server" fullword
    $ = "test" fullword
    $ = "w0fjuOVmCcP5A" fullword

    $not_gpt_tokenizer1 = "GPTTokenizer"
    $not_gpt_tokenizer2 = "GPT-4"
    $not_gpt_tokenizer3 = "const bpe = c0.concat();"
    $not_gpt_tokenizer4 = "const bpe = c0.concat(c1);"
    $not_gpt_tokenizer5 = "export default bpe;"
    $not_vale           = "github.com/errata-ai/vale"

  condition:
    12 of them and none of ($not*)
}
