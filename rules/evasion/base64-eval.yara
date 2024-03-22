import "math"

rule eval_base64 : suspicious {
	strings:
		$eval = /eval\(.{0,64}base64/
	condition:
		any of them
}

rule ruby_eval_base64_decode : critical {
  meta:
	description = "Evaluates base64 content"
  strings:
    $eval_base64_decode = "eval(Base64."
  condition:
    any of them
}

rule ruby_eval_near_enough: critical {
  meta:
	description = "Evaluates base64 content"
  strings:
    $eval = "eval("
	$base64 = "Base64"
  condition:
	  all of them and math.abs(@base64 - @eval) <= 128
}

rule ruby_eval2_near_enough: critical {
  meta:
	description = "Evaluates base64 content"
  strings:
    $eval = "eval("
	$base64 = "base64"
  condition:
	  all of them and math.abs(@base64 - @eval) <= 128
}

rule python_exec_near_enough: critical {
  meta:
	description = "Evaluates base64 content"
  strings:
    $eval = "exec("
	$base64 = "base64"
  condition:
	  all of them and math.abs(@base64 - @eval) <= 128
}


rule echo_decode_bash : suspicious {
  meta:
    hash_2021_trojan_Gafgyt_fszhv = "1794cf09f4ea698759b294e27412aa09eda0860475cd67ce7b23665ea6c5d58b"
    hash_2021_trojan_Gafgyt_malxmr = "1b5bd0d4989c245af027f6bc0c331417f81a87fff757e19cdbdfe25340be01a6"
    hash_2023_Linux_Malware_Samples_2023 = "2023eafb964cc555ec9fc4e949db9ba3ec2aea5c237c09db4cb71abba8dcaa97"
    hash_2020_trojan_vifbj = "75b32453bf6f3be414aaece313df09437b63869be876e8e847dcc620a9d6d437"
    hash_2023_Linux_Malware_Samples_aab5 = "aab526b32d703fd9273635393011a05c9c3f6204854367eb0eb80894bbcfdd42"
    hash_2023_Linux_Malware_Samples_b086 = "b086aa8017a7966f38c8dbed3268b4de938bbba1ce7317d99fc47ccb7c191965"
    hash_2020_trojan_hdfdd_sagnt = "cf369684886ba6297bc910c0fd9fb5de828db16db0cb4569e706d4ca6d0a2a2a"
    hash_2020_trojan_bkslk_genericrxoe = "d7bf34c345650c77beb2d42939efd6ded13dfd2ad330802b280934692e9914e7"
  strings:
    $echo = "echo" fullword
    $base64_decode = "base64 --decode"
    $base64_d = "base64 -d"
    $bash = "bash" fullword
    $sh = "sh" fullword
    $not_uucp = "UUCP" fullword
    $not_git = "git-core"
    $not_copyright = "Copyright (c)"
    $not_syntax = "syntax file"
  condition:
    filesize < 1048576 and $echo and ($bash or $sh) and ($base64_decode or $base64_d) and none of ($not*)
}
