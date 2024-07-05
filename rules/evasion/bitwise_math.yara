import "math"

rule large_bitwise_math : medium {
  meta:
    description = "large amounts of bitwise math"
    hash_2023_yfinancce_0_1_setup = "3bde1e9207dd331806bf58926d842e2d0f6a82424abd38a8b708e9f4e3e12049"
    hash_2023_yvper_0_1_setup = "b765244c1f8a11ee73d1e74927b8ad61718a65949e0b8d8cbc04e5d84dccaf96"
    hash_2023_aiohttpp_0_1_setup = "cfa4137756f7e8243e7c7edc7cb0b431a2f4c9fa401f2570f1b960dbc86ca7c6"
  strings:
    $x = /\-{0,1}\d{1,8} \<\< \-{0,1}\d{1,8}/
  condition:
    filesize < 128000 and #x > 10
}

rule excessive_bitwise_math : high {
  meta:
    description = "excessive use of bitwise math"
    hash_2023_yfinancce_0_1_setup = "3bde1e9207dd331806bf58926d842e2d0f6a82424abd38a8b708e9f4e3e12049"
    hash_2023_yvper_0_1_setup = "b765244c1f8a11ee73d1e74927b8ad61718a65949e0b8d8cbc04e5d84dccaf96"
    hash_2023_aiohttpp_0_1_setup = "cfa4137756f7e8243e7c7edc7cb0b431a2f4c9fa401f2570f1b960dbc86ca7c6"
  strings:
    $x = /\-{0,1}[\da-z]{1,8} \<\< \-{0,1}\d{1,8}/
    $not_Sodium = "Sodium_Core"
  condition:
    filesize < 128000 and #x > 20 and none of ($not*)
}

rule bitwise_math : low {
  meta:
    description = "uses bitwise math"
  strings:
    $x = /\-{0,1}[\da-z]{1,8} \<\< \-{0,1}\d{1,8}/
    $y = /\-{0,1}[\da-z]{1,8} \>\> \-{0,1}\d{1,8}/
  condition:
    filesize < 65535 and any of them
}

rule bidirectional_bitwise_math : medium {
  meta:
    description = "uses bitwise math in both directions"
    ref = "https://www.reversinglabs.com/blog/python-downloader-highlights-noise-problem-in-open-source-threat-detection"
    hash_2023_gmgeoip_IP2Location = "fd6123325a4b77c55ae30c641b00e28bc6c0187d6ce3d624440d70dc5376a7a4"
    hash_2023_openssl_libcrypto = "868ab5c1d1f0afa6547141f01877800d51f944a0e1f275a7bdbc38edd90ea74e"
    hash_2023_openssl_libcrypto = "868ab5c1d1f0afa6547141f01877800d51f944a0e1f275a7bdbc38edd90ea74e"
  strings:
    $x = /\-{0,1}[\da-z]{1,8} \<\< \-{0,1}\d{1,8}/
    $y = /\-{0,1}[\da-z]{1,8} \>\> \-{0,1}\d{1,8}/
  condition:
    filesize < 65535 and all of them
}

rule bitwise_python_string : medium {
  meta:
    description = "creates string using bitwise math"
    ref = "https://www.reversinglabs.com/blog/python-downloader-highlights-noise-problem-in-open-source-threat-detection"
    hash_2024_xFileSyncerx_xfilesyncerx = "c68e907642a8462c6b82a50bf4fde82bbf71245ab4edace246dd341dc72e5867"
    hash_2024_2024_d3duct1v_xfilesyncerx = "b87023e546bcbde77dae065ad3634e7a6bd4cc6056167a6ed348eee6f2a168ae"
  strings:
    $ref = /"".join\(chr\(\w{1,4} >> \w{1,3}\) for \w{1,16} in \w{1,16}/
  condition:
    filesize < 65535 and $ref
}

rule bitwise_python_string_exec_eval : high {
  meta:
    description = "creates and evaluates string using bitwise math"
    ref = "https://www.reversinglabs.com/blog/python-downloader-highlights-noise-problem-in-open-source-threat-detection"
    hash_2024_xFileSyncerx_xfilesyncerx = "c68e907642a8462c6b82a50bf4fde82bbf71245ab4edace246dd341dc72e5867"
    hash_2024_2024_d3duct1v_xfilesyncerx = "b87023e546bcbde77dae065ad3634e7a6bd4cc6056167a6ed348eee6f2a168ae"
  strings:
    $ref = /"".join\(chr\(\w{1,4} >> \w{1,3}\) for \w{1,16} in \w{1,16}/
    $exec = "exec("
    $eval = "eval("
  condition:
    filesize < 65535 and $ref and any of ($e*)
}

rule bitwise_python_string_exec_eval_nearby : critical {
  meta:
    description = "creates and executes string using bitwise math"
    ref = "https://www.reversinglabs.com/blog/python-downloader-highlights-noise-problem-in-open-source-threat-detection"
    hash_2024_xFileSyncerx_xfilesyncerx = "c68e907642a8462c6b82a50bf4fde82bbf71245ab4edace246dd341dc72e5867"
    hash_2024_2024_d3duct1v_xfilesyncerx = "b87023e546bcbde77dae065ad3634e7a6bd4cc6056167a6ed348eee6f2a168ae"
  strings:
    $ref = /"".join\(chr\(\w{1,4} >> \w{1,3}\) for \w{1,16} in \w{1,16}/
    $exec = "exec("
    $eval = "eval("
  condition:
    filesize < 65535 and $ref and any of ($e*) and (math.abs(@ref - @exec) <= 64 or (math.abs(@ref - @eval) <= 64))
}
