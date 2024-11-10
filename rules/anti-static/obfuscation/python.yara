rule Vare_Obfuscator: critical {
  meta:
    description = "obfuscated with https://github.com/saintdaddy/Vare-Obfuscator"
    filetype    = "py"

  strings:
    $var  = "__VareObfuscator__"
    $var2 = "Vare Obfuscator"

  condition:
    any of them
}

rule py_indirect_builtins: suspicious {
  meta:
    description                   = "Indirectly refers to Python builtins"
    hash_2023_yfinancce_0_1_setup = "3bde1e9207dd331806bf58926d842e2d0f6a82424abd38a8b708e9f4e3e12049"
    hash_2023_yvper_0_1_setup     = "b765244c1f8a11ee73d1e74927b8ad61718a65949e0b8d8cbc04e5d84dccaf96"
    hash_2023_aiohttpp_0_1_setup  = "cfa4137756f7e8243e7c7edc7cb0b431a2f4c9fa401f2570f1b960dbc86ca7c6"

  strings:
    $val = /getattr\(__builtins__,[ \w\.\)\)]{0,64}/

  condition:
    any of them
}

rule join_map_chr: high {
  meta:
    description = "assembles strings from character code constants"
    ref         = "https://checkmarx.com/blog/crypto-stealing-code-lurking-in-python-package-dependencies/"
    filetypes   = "py"

  strings:
    $ref = /join\(map\(chr,\[\d{1,3},\d{1,3},[\d\,]{1,32}/

  condition:
    filesize < 8KB and $ref
}

rule codecs_decode: high {
  meta:
    description               = "decodes text with an arbitrary codec"
    hash_2023_JokerSpy_shared = "5fe1790667ee5085e73b054566d548eb4473c20cf962368dd53ba776e9642272"
    hash_2023_JokerSpy_shared = "39bbc16028fd46bf4ddad49c21439504d3f6f42cccbd30945a2d2fdb4ce393a4"

  strings:
    $val = /[\w\= ]{0,16}codecs\.decode\(\'.{0,32}\'/

  condition:
    $val
}
import "math"

rule python_exec_eval_one_line: critical {
  meta:
    description = "Evaluates code from encrypted content on a single line via exec or eval"

  strings:
    $f_eval_decrypt_one_line = /eval\s{0,32}\(.{0,32}decrypt/ ascii wide
    $f_exec_decrypt_one_line = /exec\s{0,32}\(.{0,32}decrypt/ ascii wide
    $not_opa                 = "constraintsdk_decision_eval"
    $not_opa2                = " (DEPRECATED: %s)decryption"

  condition:
    any of ($f*) and none of ($not*)
}

rule python_exec_near_enough_decrypt: high {
  meta:
    description                         = "Evaluates code from encrypted content"
    hash_2024_3web_1_0_0_setup          = "7a4e6a21ac07f3d42091e3ff3345747ff68d06657d8fbd7fc783f89da99db20c"
    hash_2024_3web_py_1_0_0_setup       = "fd74f0eecebb47178ef98ac9a744daaf982a16287c78fd9cb2fe9713f542f8c5"
    hash_2024_BeaitifulSoop_1_0_0_setup = "7b2a27e5d0559625fe7f6a4e0776130880130e414c851901bbfe0cdb892dadfe"

  strings:
    $exec    = "exec(" fullword
    $decrypt = "decrypt(" fullword

  condition:
    all of them and math.abs(@decrypt - @exec) <= 256
}

rule python_exec_near_enough_fernet: critical {
  meta:
    description                         = "Evaluates code from encrypted content"
    hash_2024_3web_1_0_0_setup          = "7a4e6a21ac07f3d42091e3ff3345747ff68d06657d8fbd7fc783f89da99db20c"
    hash_2024_3web_py_1_0_0_setup       = "fd74f0eecebb47178ef98ac9a744daaf982a16287c78fd9cb2fe9713f542f8c5"
    hash_2024_BeaitifulSoop_1_0_0_setup = "7b2a27e5d0559625fe7f6a4e0776130880130e414c851901bbfe0cdb892dadfe"

  strings:
    $exec   = "exec(" fullword
    $fernet = "Fernet"

  condition:
    all of them and math.abs(@fernet - @exec) <= 256
}

rule dynamic_require: high {
  meta:
    description = "imports a library dynamically"
    filetypes   = "py"

  strings:
    $import  = "import" fullword
    $ref     = /require\(\w{2,16}\(.{0,64}\)/
    $not_str = "require(str("

  condition:
    $import and $ref and none of ($not*)
}

rule dynamic_require_decoded: critical {
  meta:
    description = "imports an obfuscated library dynamically"
    ref         = "https://blog.sucuri.net/2024/07/new-variation-of-wordfence-evasion-malware.html?ref=news.risky.biz"

  strings:
    $ref = /require\((strrev|base64_decode)\(.{0,64}\)/

  condition:
    $ref
}

rule dynamic_require_double_obscured: critical {
  meta:
    description = "imports an obfuscated library dynamically"

  strings:
    $ref = /require\(\w{0,16}\d\w{0,16}\(.{0,16}\d\w{0,16}/

  condition:
    $ref
}

rule python_eval_hex: high {
  meta:
    description = "evaluates code from an obfuscated data stream"

  strings:
    $hex   = /eval\(\"\\x\d{1,3}.{0,32}/
    $chars = /eval\(\"\\\d{1,3}.{0,32}/

  condition:
    any of them
}

rule python_eval_marshal: high {
  meta:
    description = "evaluates code from marshalled data"

  strings:
    $marshal = "eval(marshal.loads"
    $json    = "eval(json.loads"

  condition:
    any of them
}

rule python_eval_gzip: high {
  meta:
    description = "evaluates code from gzip content"

  strings:
    $ref = /eval\(.{0,32}\(gzip\.decompress\(b.{0,32}/

  condition:
    any of them
}

rule python_exec_hex: high {
  meta:
    description = "executs code from an obfuscated data stream"

  strings:
    $hex   = /exec\(\"\\x\d{1,3}.{0,32}/
    $chars = /exec\(\"\\\d{1,3}.{0,32}/

  condition:
    any of them
}

rule python_exec_marshal: high {
  meta:
    description = "evaluates code from marshalled data"

  strings:
    $marshal = "exec(marshal.loads"
    $json    = "exec(json.loads"

  condition:
    any of them
}

rule python_exec_gzip: high {
  meta:
    description = "executes code from gzip content"

  strings:
    $ref = /exec\(.{0,32}\(gzip\.decompress\(b.{0,32}/

  condition:
    any of them
}

rule fernet_base64: high {
  meta:
    description = "Decodes base64, uses Fernet"
    filetypes   = "py"

  strings:
    $fernet     = "Fernet" fullword
    $fernet2    = "fernet" fullword
    $bdecode_64 = "b64decode" fullword
    $bdecode_32 = "b32decode" fullword
    $o1         = "decode()"
    $o2         = "decompress("
    $o4         = "bytes.fromhex"
    $o5         = "decrypt("
    $o6         = "exec("
    $o7         = "eval("

    $not_utils         = "from cryptography import utils"
    $not_fernet_itself = "class Fernet"

  condition:
    filesize < 2MB and any of ($fernet*) and any of ($bdecode*) and any of ($o*) and none of ($not*)
}

rule python_long_hex: medium {
  meta:
    description = "contains a large hexadecimal string variable"
    filetypes   = "py"

  strings:
    $assign = /\w{0,16}=["'][a-z0-9]{1024}/

  condition:
    filesize < 1MB and $assign
}

rule python_long_hex_multiple: high {
  meta:
    description = "contains multiple large hexadecimal string variables"
    filetypes   = "py"

  strings:
    $assign = /\w{0,16}=["'][a-z0-9]{1024}/

  condition:
    filesize < 1MB and #assign > 3
}

rule python_hex_decimal: high {
  meta:
    description = "contains a large amount of escaped hex/decimal content"
    filetypes   = "py"

  strings:
    $f_return = "return"
    $f_decode = "decode("
    $f_eval   = "eval("
    $f_exec   = "exec("

    $trash = /\\x{0,1}\d{1,3}\\/

    $not_testing_t = "*testing.T" fullword

  condition:
    filesize < 1MB and any of ($f*) and #trash in (filesize - 1024..filesize) > 100 and none of ($not*)
}

rule dumb_int_compares: high {
  meta:
    description = "compares arbitrary integers, likely encoding something"
    filetypes   = "py"

  strings:
    $import              = "import" fullword
    $decode_or_b64decode = /if \d{2,16} == \d{2,16}/

  condition:
    filesize < 1MB and all of them
}

rule py_lib_alias_val: medium {
  meta:
    description               = "aliases core python library to an alternate name"
    hash_2022_requests_init   = "4b62b48e754fe824ab4f9d5272d172881d177c8f07f4db7b12acc44400f8e208"
    hash_2022_requests_compat = "cb19ed54e4841c632b9fb14daffdf61046a6d5934074f45d484d77ff2687cd39"
    hash_2022_tests_compat    = "d58ff5e3167de0140a667cc51427f809c552e485875c95b9dad43ce13ba15083"

  strings:
    $val = /from \w{2,16} import \w{2,16} as \w{1,32}/ fullword

  condition:
    $val
}

rule multi_decode_3: high {
  meta:
    description = "multiple (3+) levels of decoding"
    filetypes   = "py"

  strings:
    $return              = "return"
    $decode_or_b64decode = /\.[b64]{0,3}decode\(.{0,256}\.[b64]{0,3}decode\(.{0,256}\.[b64]{0,3}decode/

  condition:
    filesize < 1MB and all of them
}

rule multi_decode: medium {
  meta:
    description = "multiple (2) levels of decoding"
    filetypes   = "py"

  strings:
    $return              = "return"
    $decode_or_b64decode = /\.[b64]{0,3}decode\(.{0,32}\.[b64]{0,3}decode\(/

  condition:
    filesize < 1MB and all of them
}

rule rename_requests: medium {
  meta:
    description                              = "imports 'requests' library and gives it another name"
    hash_2021_DiscordSafety_init             = "05c23917c682326179708a1d185ea88632d61522513f08d443bfd5c065612903"
    hash_2021_DiscordSafety_0_1_setup        = "7dfa21dda6b275952ee8410a19b0f38e1071588be5894cf052329ca106eae6e1"
    hash_2023_barcodegeneratorqr_1_0_3_setup = "ce066194bbf5c80c2ebe98ad20db41cf35d2fc4faf370a60ff2b129a836443a9"

  strings:
    $ref = /import requests as \w{0,64}/

  condition:
    filesize < 512KB and all of them
}

rule rename_requests_2char: high {
  meta:
    description                              = "imports 'requests' library and gives it a two-letter name"
    hash_2021_DiscordSafety_init             = "05c23917c682326179708a1d185ea88632d61522513f08d443bfd5c065612903"
    hash_2021_DiscordSafety_0_1_setup        = "7dfa21dda6b275952ee8410a19b0f38e1071588be5894cf052329ca106eae6e1"
    hash_2023_barcodegeneratorqr_1_0_3_setup = "ce066194bbf5c80c2ebe98ad20db41cf35d2fc4faf370a60ff2b129a836443a9"

  strings:
    $ref = /import requests as \w{2}/

  condition:
    filesize < 65535 and all of them
}

rule rename_os: high {
  meta:
    description = "imports 'os' library and gives it another name"

  strings:
    $ref            = /import os as \w{0,64}/
    $not_underscore = "import os as _os"
    $not_gos        = "import os as gos"

  condition:
    filesize < 65535 and $ref and none of ($not*)
}

rule rename_marshal: critical {
  meta:
    description                       = "imports 'marshal' library and gives it another name"
    hash_2021_DiscordSafety_init      = "05c23917c682326179708a1d185ea88632d61522513f08d443bfd5c065612903"
    hash_2021_DiscordSafety_0_1_setup = "7dfa21dda6b275952ee8410a19b0f38e1071588be5894cf052329ca106eae6e1"

  strings:
    $ref = /import marshal as \w{0,64}/

  condition:
    filesize < 512KB and all of them
}

rule rename_base64: critical {
  meta:
    description                          = "imports 'base64' library and gives it another name"
    hash_2022_very_hackerman_0_0_1_setup = "66a4a39a3c79a24bdf150cb87106920442a3db20a59810eb3e06149b028c7bff"
    hash_2022_example_package_init       = "5c0db191458fe648d6799d1461d20e79e65986ba6db522db3737ebbf99c577cb"
    hash_2022_xoloaghvurilnh_init        = "87a23edfa8fbcc13d1a25b9ac808dbc36c417fda508f98186455a7991a52b6c0"

  strings:
    $ref = /import base64 as \w{0,64}/

  condition:
    filesize < 1MB and all of them
}

rule rename_zlib: high {
  meta:
    description                          = "imports 'base64' library and gives it another name"
    hash_2022_very_hackerman_0_0_1_setup = "66a4a39a3c79a24bdf150cb87106920442a3db20a59810eb3e06149b028c7bff"
    hash_2022_example_package_init       = "5c0db191458fe648d6799d1461d20e79e65986ba6db522db3737ebbf99c577cb"
    hash_2022_xoloaghvurilnh_init        = "87a23edfa8fbcc13d1a25b9ac808dbc36c417fda508f98186455a7991a52b6c0"

  strings:
    $ref = /import zlib as \w{0,64}/

  condition:
    filesize < 512KB and all of them
}
