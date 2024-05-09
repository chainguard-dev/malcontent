import "math"

rule python_popen_near_enough : critical {
  meta:
    description = "runs programs based on base64 content"
    hash_2024_2024_PAN_OS_Upstyle_update_base64_payload2 = "5c4943cbcc683fe368f13e5609b9c79ace3b9d9cee7aa1009d5b1792b3bd9c5b"
  strings:
    $popen = "os.popen("
    $base64 = "b64decode"
  condition:
    all of them and math.abs(@base64 - @popen) < 128
}
