import "hash"

rule py_indirect_builtins: suspicious {
  meta:
    description = "Indirectly refers to Python builtins"
    filetypes   = "py"

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
    $ref  = /join\(map\(chr,\[\d{1,3}, {0,2}\d{1,3}, {0,2}[\d\,]{1,32}/
    $ref2 = /join\(chr\([a-z]{1,5}\) for [a-z]{1,5} in \[\d{1,3}, {0,2}\d{1,3}, {0,2}[\d\,]{1,32}/

  condition:
    filesize < 10MB and any of them
}

rule for_join_ord: high {
  meta:
    description = "decodes numbers from an obfuscated string"
    filetypes   = "py"

  strings:
    $ref = /for [\w]{1,10} in ["']{2}\.join\(chr\(ord\(\w{1,8}\)[-\w\), ]{0,16}/

  condition:
    filesize < 10MB and any of them
}

rule codecs_decode: high {
  meta:
    description = "decodes text with an arbitrary codec"
    filetypes   = "py"

  strings:
    $val = /[\w\= ]{0,16}codecs\.decode\(\'.{0,32}\'/

  condition:
    $val
}

import "math"

rule python_exec_eval_one_line: critical {
  meta:
    description = "Evaluates code from encrypted content on a single line via exec or eval"
    filetypes   = "py"

  strings:
    $f_eval_decrypt_one_line = /eval\s{0,32}\(.{0,32}decrypt/ ascii wide
    $f_exec_decrypt_one_line = /exec\s{0,32}\(.{0,32}decrypt/ ascii wide
    $not_opa                 = "constraintsdk_decision_eval"
    $not_opa2                = " (DEPRECATED: %s)decryption"

  condition:
    any of ($f*) and none of ($not*)
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
    filetypes   = "py"

  strings:
    $ref = /require\((strrev|base64_decode)\(.{0,64}\)/

  condition:
    $ref
}

rule dynamic_require_double_obscured: critical {
  meta:
    description = "imports an obfuscated library dynamically"
    filetypes   = "py"

  strings:
    $ref = /require\(\w{0,16}\d\w{0,16}\(.{0,16}\d\w{0,16}/

  condition:
    $ref
}

rule python_eval_hex: high {
  meta:
    description = "evaluates code from an obfuscated data stream"
    filetypes   = "py"

  strings:
    $hex   = /eval\(\"\\x\d{1,3}.{0,32}/
    $chars = /eval\(\"\\\d{1,3}.{0,32}/

  condition:
    any of them
}

rule python_eval_marshal: high {
  meta:
    description = "evaluates code from marshalled data"
    filetypes   = "py"

  strings:
    $marshal = "eval(marshal.loads"
    $json    = "eval(json.loads"

  condition:
    any of them
}

rule python_eval_gzip: high {
  meta:
    description = "evaluates code from gzip content"
    filetypes   = "py"

  strings:
    $ref = /eval\(.{0,32}\(gzip\.decompress\(b.{0,32}/

  condition:
    any of them
}

rule python_exec_hex: high {
  meta:
    description = "executs code from an obfuscated data stream"
    filetypes   = "py"

  strings:
    $hex   = /exec\(\"\\x\d{1,3}.{0,32}/
    $chars = /exec\(\"\\\d{1,3}.{0,32}/

  condition:
    any of them
}

rule python_exec_marshal: high {
  meta:
    description = "evaluates code from marshalled data"
    filetypes   = "py"

  strings:
    $marshal = "exec(marshal.loads"
    $json    = "exec(json.loads"

  condition:
    any of them
}

rule python_exec_gzip: high {
  meta:
    description = "executes code from gzip content"
    filetypes   = "py"

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
    filesize < 10MB and any of ($f*) and #trash in (filesize - 1024..filesize) > 100 and none of ($not*)
}

rule dumb_int_compares: high {
  meta:
    description = "compares arbitrary integers, likely encoding something"
    filetypes   = "py"

  strings:
    $import              = "import" fullword
    $decode_or_b64decode = /if \d{2,16} == \d{2,16}/

  condition:
    filesize < 10MB and all of them
}

rule py_lib_alias_val: medium {
  meta:
    description = "aliases core python library to an alternate name"

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
    filesize < 10MB and all of them
}

rule multi_decode: medium {
  meta:
    description = "multiple (2) levels of decoding"
    filetypes   = "py"

  strings:
    $return              = "return"
    $decode_or_b64decode = /\.[b64]{0,3}decode\(.{0,32}\.[b64]{0,3}decode\(/

  condition:
    filesize < 10MB and all of them
}

rule rename_requests: medium {
  meta:
    description = "imports 'requests' library and gives it another name"
    filetypes   = "py"

  strings:
    $ref = /import requests as \w{0,64}/

  condition:
    filesize < 10MB and all of them
}

rule rename_requests_2char: high {
  meta:
    description = "imports 'requests' library and gives it a shorter name"
    filetypes   = "py"

  strings:
    $ref = /import requests as \w{1,2}/ fullword

  condition:
    filesize < 32KB and all of them
}

rule rename_os: high {
  meta:
    description = "imports 'os' library and gives it another name"
    filetypes   = "py"

  strings:
    $ref            = /import os as \w{0,64}/
    $not_underscore = "import os as _os"
    $not_gos        = "import os as gos"

  condition:
    filesize < 65535 and $ref and none of ($not*)
}

rule rename_marshal: critical {
  meta:
    description = "imports 'marshal' library and gives it another name"
    filetypes   = "py"

  strings:
    $ref = /import marshal as \w{0,64}/

  condition:
    filesize < 10MB and all of them
}

rule rename_base64: critical {
  meta:
    description = "imports 'base64' library and gives it another name"
    filetypes   = "py"

  strings:
    $ref = /import base64 as \w{0,64}/

    $not_numcodecs1 = "Codec providing base64 compression via the Python standard library."
    $not_numcodecs2 = "codec_id = \"base64\""
    $not_numcodecs3 = "# normalise inputs"
    $not_numcodecs4 = "# do compression"
    $not_open_clip1 = "class ResampledShards2(IterableDataset)"
    $not_open_clip2 = "class SyntheticDataset(Dataset)"

  condition:
    filesize < 10MB and all of them and none of ($not*)
}

rule rename_zlib: high {
  meta:
    description = "imports 'base64' library and gives it another name"
    filetypes   = "py"

  strings:
    $ref = /import zlib as \w{0,64}/

  condition:
    filesize < 10MB and all of them
}

rule too_many_lambdas_small: high {
  meta:
    description = "lambda based obfuscation"
    filetypes   = "py"

  strings:
    $ref = /lambda \W: \W [\+\-\*]/

  condition:
    filesize < 8KB and #ref > 30
}

rule too_many_lambdas_large: high {
  meta:
    description = "lambda based obfuscation"
    filetypes   = "py"

  strings:
    $ref = /lambda \W: \W [\+\-\*]/

  condition:
    filesize < 10MB and #ref > 100
}

rule lambda_funk: high {
  meta:
    description = "likely obfuscated with lambda functions"
    filetypes   = "py"

  strings:
    $ = "__builtins__.__dict__"
    $ = "(lambda"
    $ = ".decode(bytes("
    $ = "b64decode("
    $ = ".decompress("
    $ = ".decode('utf-8'))"

  condition:
    filesize < 10MB and 80 % of them
}

rule lambda_funk_high: high {
  meta:
    description = "obfuscated with lambda expressions"
    filetypes   = "py"

  strings:
    $ = "__builtins__.__dict__"
    $ = "(lambda"
    $ = ".decode(bytes("
    $ = "b64decode("
    $ = ".decompress("
    $ = ".decode('utf-8'))"

  condition:
    filesize < 10MB and all of them
}

rule confusing_function_name: high {
  meta:
    description = "obfuscated with confusing function names"
    filetypes   = "py"

  strings:
    $def    = /def [Il]{6,64}/
    $eq     = /[Il]{6,64} = / fullword
    $return = /return [Il]{6,64}\(/
    $func   = / \+ [Il]{6,64}\([Il]{6,64}\)/
    $func2  = /\)\+[Il]{6,64}\([Il]{6,64}\)\+/

  condition:
    filesize < 10MB and any of them
}

rule decompress_base64_entropy: high {
  meta:
    description = "hidden base64-encoded compressed content"
    filetypes   = "py"

  strings:
    $k_lzma         = "lzma"
    $k_gzip         = "gzip"
    $k_zlib         = "zlib"
    $f_bytes        = "bytes("
    $f_decode       = "decode("
    $f_decompress   = "decompress("
    $f_eval         = "eval("
    $f_exec         = "exec("
    $b64decode_long = /b64decode\(\"[\+\=\w\/]{96}/

  condition:
    filesize < 10MB and any of ($k*) and $b64decode_long and any of ($f*)
}

rule join: low {
  meta:
    description = "joins array together with an empty delimiter"
    filetypes   = "py"

  strings:
    $join        = "''.join("
    $join_double = "\"\".join("

  condition:
    any of them
}

rule join_chr_array: medium {
  meta:
    description = "joins lengthy character array"
    filetypes   = "py"

  strings:
    $ref     = /[a-z]{1,64}\s{0,2}=\s{0,2}\[\d{1,5},\s{0,2}\d{1,5},\s{0,2}\d{1,5},\s{0,2}\d{1,5},\s{0,2}\d{1,5},\s{0,2}\d{1,5},\s{0,2}\d{1,5},\s{0,2}\d{1,5},\s{0,2}\d{1,5},\s{0,2}\d{1,5},\s{0,2}\d{1,5},\s{0,2}\d{1,5},\s{0,2}\d{1,5},\s{0,2}\d{1,5},\s{0,2}\d{1,5},\s{0,2}\d{1,5},\s{0,2}/
    $chr_int = "chr(int("

  condition:
    join and all of them
}

rule join_chr_array_exec: high {
  meta:
    description = "joins lengthy character array and executes arbitrary code"
    filetypes   = "py"

  strings:
    $val = /exec\(\w{1,32}\)/ fullword

  condition:
    join_chr_array and all of them
}

rule join_chr_array_math: high {
  meta:
    description = "joins obfuscated character array"
    filetypes   = "py"

  strings:
    $ref2 = /chr\(int\([a-z]{1,32}\)\s{0,2}[\-\*\+\^]\s{0,2}\w{1,32}/

  condition:
    join_chr_array and all of them
}

rule join_chr_array_exec_math: critical {
  meta:
    description = "joins obfuscated character array and executes arbitrary code"
    filetypes   = "py"

  strings:
    $val = /exec\(\w{1,32}\)/ fullword

  condition:
    join_chr_array_math and all of them
}

rule urllib_as_int_array: critical {
  meta:
    description = "hides urllib code as an array of integers"

  strings:
    $urllib_dot  = "117,114,108,108,105,98,46"
    $urllib_dot2 = "117, 114, 108, 108, 105, 98, 46"

  condition:
    filesize < 10MB and any of them
}

rule import_manipulator: critical {
  meta:
    description = "manipulates globals and imports into executing obfuscated code"
    filetypes   = "py"

  strings:
    $import  = "__import__("
    $getattr = "getattr("
    $setattr = "setattr("
    $update  = "update("
    $chr     = /chr\(\w{1,8}\)/
    $globals = "globals"
    $dict    = "__dict__"
    $def     = "def "

  condition:
    // a91160135598f3decc8ca9f9b019dcc5e1d73e79ebe639548cd9ee9e6d007ea6 is the sha256 hash
    // for https://github.com/pypy/pypy/blob/main/lib-python/2.7/pickle.py
    // 44cdd1503ae0b1d7c9e5eb79fd624a7e51780b7a8fc6cfbc68b49ef7c6e63abc is the sha256 hash
    // https://github.com/jython/jython/blob/v2.7.4/Lib/pickle.py
    filesize < 10MB and (hash.sha256(0, filesize) != "a91160135598f3decc8ca9f9b019dcc5e1d73e79ebe639548cd9ee9e6d007ea6") and
    (hash.sha256(0, filesize) != "44cdd1503ae0b1d7c9e5eb79fd624a7e51780b7a8fc6cfbc68b49ef7c6e63abc") and all of them
}

rule bloated_hex_python: high {
  meta:
    description = "python script bloated with obfuscated content"
    filetypes   = "py"

  strings:
    $f_unhexlify = "unhexlify" fullword
    $f_join      = "join("
    $f_split     = "split" fullword
    $f_lambda    = "lambda" fullword
    $f_ord       = "ord" fullword
    $f_def       = "def" fullword
    $f_decode    = "decode" fullword
    $f_exec      = "exec" fullword
    $f_eval      = "eval"
    $f_alphabet  = "abcdefghijkl"

    $not_js        = "function("
    $not_highlight = "highlight"

  condition:
    filesize > 512KB and filesize < 10MB and 90 % of ($f*) and none of ($not*)
}
