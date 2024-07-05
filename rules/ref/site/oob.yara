
rule interact_sh : high {
  meta:
	description = "uses interactsh for OOB interaction gathering"
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
