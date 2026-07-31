rule common_username_block_list: high {
  meta:
    description = "avoids execution if user has a particular name"
    ref         = "https://www.zscaler.com/blogs/security-research/technical-analysis-bandit-stealer"

  strings:
    $user_3u2v9m8            = "3u2v9m8" fullword
    $user_8Nl0ColNQ5bq       = "8Nl0ColNQ5bq" fullword
    $user_8VizSM             = "8VizSM" fullword
    $user_Abby               = "Abby" fullword
    $user_BvJChRPnsxn        = "BvJChRPnsxn" fullword
    $user_Frank              = "Frank" fullword
    $user_HEUeRzl            = "HEUeRzl" fullword
    $user_Harry_Johnson      = "Harry Johnson" fullword
    $user_John               = "John" fullword
    $user_Julia              = "Julia" fullword
    $user_Lisa               = "Lisa" fullword
    $user_Louise             = "Louise" fullword
    $user_Lucas              = "Lucas" fullword
    $user_PateX              = "PateX" fullword
    $user_PqONjHVwexsS       = "PqONjHVwexsS" fullword
    $user_PxmdUOpVyx         = "PxmdUOpVyx" fullword
    $user_RDhJ0CNFevzX       = "RDhJ0CNFevzX" fullword
    $user_RGzcBUyrznReg      = "RGzcBUyrznReg" fullword
    $user_SqgFOf3G           = "SqgFOf3G" fullword
    $user_User01             = "User01" fullword
    $user_WDAGUtilityAccount = "WDAGUtilityAccount" fullword
    $user_fred               = "fred" fullword
    $user_george             = "george" fullword
    $user_h7dk1xPr           = "h7dk1xPr" fullword
    $user_hmarc              = "hmarc" fullword
    $user_kEecfMwgj          = "kEecfMwgj" fullword
    $user_lmVwjj9b           = "lmVwjj9b" fullword
    $user_mike               = "mike" fullword
    $user_patex              = "patex" fullword
    $user_server             = "server" fullword
    $user_test               = "test" fullword
    $user_w0fjuOVmCcP5A      = "w0fjuOVmCcP5A" fullword

    $notgrp_gpt1 = "GPTTokenizer"
    $notgrp_gpt2 = "GPT-4"
    $notgrp_gpt3 = "const bpe = c0.concat();"
    $notgrp_gpt4 = "const bpe = c0.concat(c1);"
    $notgrp_gpt5 = "export default bpe;"

    $not_vale = "github.com/errata-ai/vale"

  condition:
    // The $notgrp_gpt* strings jointly identify the gpt-tokenizer BPE module; "GPT-4" on its
    // own says nothing. $notgrp_gpt3 and $notgrp_gpt4 are alternate spellings of the same
    // generated line and cannot co-occur, so require two of the five rather than all of them.
    // The reference count selects $user* explicitly because `them` would include the
    // suppression strings once the guard no longer requires none of them to match.
    12 of ($user*) and not 2 of ($notgrp_gpt*) and none of ($not_*)
}
