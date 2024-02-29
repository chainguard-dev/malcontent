rule opaque_binary : suspicious {
  meta:
    hash_2023_MacOS_applet = "54db4cc34db4975a60c919cd79bb01f9e0c3e8cf89571fee09c75dfff77a0bcd"
    hash_2021_CDDS_arch = "a63466d09c3a6a2596a98de36083b6d268f393a27f7b781e52eeb98ae055af97"
    hash_2019_Macma_CDDS_at = "341bc86bc9b76ac69dca0a48a328fd37d74c96c2e37210304cfa66ccdbe72b27"
    hash_2018_org_logind_ctp_archive_helper = "562c420921f5146273b513d17b9f470a99bd676e574c155376c3eb19c37baa09"
    hash_2018_org_logind_ctp_archive = "02e4d0e23391bbbb75c47f5db44d119176803da74b1c170250e848de51632ae9"
    hash_2017_MacOS_logind = "1cf36a2d8a2206cb4758dcdbd0274f21e6f437079ea39772e821a32a76271d46"
    hash_2017_FlashBack = "8d56d09650ebc019209a788b2d2be7c7c8b865780eee53856bafceffaf71502c"
    hash_1980_FruitFly_A_a94d = "a94dd8bfca34fd6ca3a475d6be342d236b39fbf0c2ab90b2edff62bcdbbe5d37"
  strings:
    $word_with_spaces = /[a-z]{2,} [a-z]{2,}/
	$not_gmon_start = "__gmon_start__"
	$not_usage = "usage:" fullword
  condition:
	// matches elf or macho
    filesize < 52428800 and (uint32(0) == 1179403647 or uint32(0) == 4277009102 or uint32(0) == 3472551422 or uint32(0) == 4277009103 or uint32(0) == 3489328638 or uint32(0) == 3405691582 or uint32(0) == 3199925962) and #word_with_spaces < 4 and none of ($not*)
}
