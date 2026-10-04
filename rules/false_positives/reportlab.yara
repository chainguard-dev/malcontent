rule reportlab_lib_utils: override {
  meta:
    description            = "reportlab/lib/utils.py"
    php_eval_base64_decode = "harmless"

  strings:
    $copyright        = /Copyright ReportLab Europe Ltd\./
    $rl_tempfile      = /reportlab\.lib\.rltempfile/
    $literal_eval_b64 = /literal_eval\(base64_decodebytes\(/
    $eval_b64         = /eval\(base64_decode/

  condition:
    // every eval(base64_decode must be decode_label()'s literal_eval call
    filesize < 100KB and #eval_b64 == #literal_eval_b64 and all of them
}
