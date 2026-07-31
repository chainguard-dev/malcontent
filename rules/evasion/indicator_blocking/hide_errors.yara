rule php_suppressed_include: high {
  meta:
    description = "Includes a file, suppressing errors"
    credit      = "Inspired by DodgyPHP rule in php-malware-finder"
    filetypes   = "php"

  strings:
    // $include requires the argument opener a PHP include actually uses: "(", a
    // quote, or "$". The previous unanchored /@\s*include\s*/ also matched the
    // Sass at-rule list "@extend|@include|@import", the Chroma lexer pattern
    // "(@include)( ", Doxygen's "@includelineno" and GraphQL's "@include(if:" --
    // which is all the generic "snippet"/"copyright" exclusions were papering over.
    $php     = "<?php"
    $include = /@[ \t]{0,2}include(_once){0,1}[ \t]{0,4}[\('"\$]/

  condition:
    filesize < 5242880 and $php and $include
}
