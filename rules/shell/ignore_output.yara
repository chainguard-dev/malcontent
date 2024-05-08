
rule ignore_output_val : notable {
  meta:
    description = "Runs shell commands but throws output away"
    hash_2023_Downloads_6e35 = "6e35b5670953b6ab15e3eb062b8a594d58936dd93ca382bbb3ebdbf076a1f83b"
    hash_2023_Downloads_9929 = "99296550ab836f29ab7b45f18f1a1cb17a102bb81cad83561f615f3a707887d7"
    hash_2023_Downloads_Chrome_Update = "eed1859b90b8832281786b74dc428a01dbf226ad24b182d09650c6e7895007ea"
  strings:
    $kind_bash = /[\/\-\w ]{0,64}\> {0,2}\/dev\/null 2> {0,2}&1/
    $kind_both = /[\/\-\w ]{0,64}\> {0,2}\/dev\/null 2> {0,2}\/dev\/null/
    $kind_all = /[\/\-\w ]{0,64}> \/dev\/null 2>&1/
    $not_declare = /declare -\w [\w]{0,64} >/
  condition:
    any of ($kind*) and none of ($not*)
}
