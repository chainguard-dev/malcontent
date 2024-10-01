
rule base64_shell_decode : medium {
  meta:
    description = "calls base64 command to decode strings"
    hash_2023_Linux_Malware_Samples_1794 = "1794cf09f4ea698759b294e27412aa09eda0860475cd67ce7b23665ea6c5d58b"
    hash_2023_Linux_Malware_Samples_1b5b = "1b5bd0d4989c245af027f6bc0c331417f81a87fff757e19cdbdfe25340be01a6"
    hash_2023_Linux_Malware_Samples_2023 = "2023eafb964cc555ec9fc4e949db9ba3ec2aea5c237c09db4cb71abba8dcaa97"
  strings:
    $base64_d = "base64 -d"
    $base64_d_b64 = "base64 -d" base64
    $base64_D = "base64 -D"
    $base64_D_b64 = "base64 -D" base64
    $base64_decode = "base64 --decode"
    $base64_decode_b64 = "base64 --decode" base64
    $base64_re = /base64 [\w\%\@\- ]{0,16} -[dD]/
    $not_example = "base64 --decode | keybase"
  condition:
    any of ($base64*) and none of ($not*)
}
