rule go_1_17_override: override {
  meta:
    description                            = "linux_amd64/link"
    ARKBIRD_SOLG_APT_APT34_RDAT_Feb_2021_1 = "low"

  strings:
    $build_id = "OZ4MIHRt5yYNzPxU6QuH/qAeXWMvY1RJrUXB6xka1/4fdCwddvzTvjJBZrCo2S/DCU7CoUCdrRvbKi6ROH6"

  condition:
    all of them
}
