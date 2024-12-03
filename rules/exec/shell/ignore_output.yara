rule ignore_output_val: medium {
  meta:
    description = "Runs shell commands but throws output away"

  strings:
    $kind_bash   = /[\/\-\.\w ]{0,64}\> {0,2}\/dev\/null 2> {0,2}&1/
    $kind_both   = /[\/\-\.\w ]{0,64}\> {0,2}\/dev\/null 2> {0,2}\/dev\/null/
    $kind_all    = /[\/\-\.\w ]{0,64}> \/dev\/null 2>&1/
    $not_declare = /declare -\w [\w]{0,64} >/

  condition:
    any of ($kind*) and none of ($not*)
}
