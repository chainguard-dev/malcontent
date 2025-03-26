rule exec_regex: override {
  meta:
    description                         = "csv_builder_spec.rb"
    SEKOIA_Technique_Csv_Dde_Exec_Regex = "low"

  strings:
    $example1 = "shared_examples 'excel sanitization' do"
    $example2 = "'sanitizes dangerous characters at the beginning of a column'"
    $example3 = "'does not sanitize safe symbols at the beginning of a column'"
    $example4 = "'when dangerous characters are after a line break'"
    $example5 = "'does not append single quote to description'"

  condition:
    filesize < 8192 and all of them
}
