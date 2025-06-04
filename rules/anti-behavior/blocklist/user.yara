rule common_username_block_list: critical {
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

    $not_grafana1   = "self.webpackChunkgrafana=self.webpackChunkgrafana||[]"
    $not_grafana2   = "The Grafana LLM plugin is not installed."
    $not_grafana3   = "grafana.debug.scenes"
    $not_jitsu      = "jitsu.com"
    $not_redpanda   = "redpanda"
    $not_sqlmetal1  = "sqlmetal"
    $not_sqlmetal2  = "asqlmetal_test_net_2_0, PublicKey=0024000004800000940000000602000000240000525341310004000001000100c5753d8c47f40083f549016a5711238ac8ec297605abccd3dc4b6d0f280b4764eb2cc58ec4e37831edad7e7a07b8fe4a9cbb059374c0cc047aa28839fed7176761813caf6a2ffa0bff9afb50ead56dd3f56186a663962a12b830c2a70eb70ec77823eb5750e5bdef9e01d097c30b5c5463c3d07d3472b58e4c02f2792309259f"
    $not_sqlmetal3  = "asqlmetal_test_net_4_0, PublicKey=0024000004800000940000000602000000240000525341310004000001000100c5753d8c47f40083f549016a5711238ac8ec297605abccd3dc4b6d0f280b4764eb2cc58ec4e37831edad7e7a07b8fe4a9cbb059374c0cc047aa28839fed7176761813caf6a2ffa0bff9afb50ead56dd3f56186a663962a12b830c2a70eb70ec77823eb5750e5bdef9e01d097c30b5c5463c3d07d3472b58e4c02f2792309259f"
    $not_wireshark  = "wireshark.org"
    $gpt_tokenizer1 = "GPTTokenizer"
    $gpt_tokenizer2 = "GPT-4"

  condition:
    8 of them and none of ($not*) and (#gpt_tokenizer1 < 3 and #gpt_tokenizer2 < 65)
}
