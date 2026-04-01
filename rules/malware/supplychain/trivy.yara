import "hash"

rule trivy_2026_03: critical {
  meta:
    description = "Contains IOCs from the 2026/03/19 Trivy compromise"

  strings:
    $actions_commit = "8afa9b9f9183b4e00c46e2b82d34047e3c177bd0"
    $domain1        = "scan.aquasecurtiy.org"
    $domain2        = "tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io"
    $ip             = "45.148.10.212"

  condition:
    (hash.sha256(0, filesize) == "3350da5e45f99ec86eec5cb87efe84241d82a019822e4270facb818519778d12")  // brew tarball
    or (hash.sha256(0, filesize) == "ef8a2c83882852c92d01a7356ca7a362aef98d1eae332ab48f993ea0ef3d8fe0")  // workflow YAML
    or (hash.sha256(0, filesize) == "18a24f83e807479438dcab7a1804c51a00dafc1d526698a66e0640d1e5dd671a")  // entrypoint.sh
    or (hash.sha256(0, filesize) == "c0d85c24e72327453868628991e3b8053b6dbb08e3c52bd29712d845e453f469")  // arm64_tahoe (brew)
    or (hash.sha256(0, filesize) == "2376e3929b5c080f5d6acc4ebd6f94cc52557afe1287c927f5d25178c46026a6")  // arm64_sequoia (brew)
    or (hash.sha256(0, filesize) == "aa279a677b68b3dc1ce5e615c0de05d6a446d34314060e56e0e74901aa8d6425")  // arm64_sonoma (brew)
    or (hash.sha256(0, filesize) == "32a0cc6e2e2a1a5cb281383c6d87997f0728c7aa1abbee68dc33e7c1583b7ddf")  // sonoma (brew)
    or (hash.sha256(0, filesize) == "65772bde6ffadea570171fadf208786852ace51516e88649c4f0de1fc5d1e7c1")  // arm64_linux (brew)
    or (hash.sha256(0, filesize) == "729aa7df0d1f026ec18333fafc5f9a35547dc3f42a524bf83abc2017bb75833e")  // x86_64_linux (brew)
    or any of them
}
