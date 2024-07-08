
rule interact_sh : high {
  meta:
    description = "uses interactsh for OOB interaction gathering"
    hash_1985_package_index = "19dc05db0219df84f303bde62d37dbf7ece4e2825daa98e27ba087cc3594431d"
    hash_1985_package_index = "19dc05db0219df84f303bde62d37dbf7ece4e2825daa98e27ba087cc3594431d"
    hash_1985_package_index = "19dc05db0219df84f303bde62d37dbf7ece4e2825daa98e27ba087cc3594431d"
  strings:
    $ref = /[\w]{8,32}\.interactsh\.com/
  condition:
    $ref
}

rule burb_collab : high {
  meta:
    description = "uses burpcollaborator for OOB interaction gathering"
  strings:
    $ref = /[\w]{8,32}\.burpcollaborator\.net/
  condition:
    $ref
}
