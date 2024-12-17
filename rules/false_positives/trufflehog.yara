rule trufflehog_override: override {
  meta:
    description            = "github.com/trufflesecurity/trufflehog"
    suspected_data_stealer = "medium"
    discord_bot            = "medium"
    iplookup_website       = "medium"
    download_sites         = "medium"
    file_io_uploader       = "medium"

  strings:
    $ref = "github.com/trufflesecurity/trufflehog"

  condition:
    filesize > 50MB and filesize < 200MB and any of them
}
