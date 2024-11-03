rule credit_card: medium {
  meta:
    description = "references 'credit card'"

  strings:
    $credit_card = "credit card"
    $Credit_Card = "Credit Card"

  condition:
    any of them
}
