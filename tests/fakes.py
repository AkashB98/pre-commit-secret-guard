"""Fake secret values, assembled by concatenation so no literal
real-looking secret string sits in the test sources."""

AWS = "AKIA" + "Z7XK2P9QW4RT8N3M"
AWS_DOC = "AKIA" + "IOSFODNN7EXAMPLE"
GITHUB = "ghp_" + "x7K9mQ2wErTyUiOpAsDfGhJkLzXcVbN3mQ"
STRIPE_LIVE = "sk_" + "live_" + "51H7xK9mQ2wErTyUiOpAsDfG"
STRIPE_DOC = "sk_test_" + "4eC39HqLyjWDarjtT1zdp7dc"
CARD = "4532" + "0151" + "1283" + "0366"          # Luhn-valid, not a test card
CARD_SPACED = "4532" + " 0151" + " 1283" + " 0366"
TEST_CARD = "4111" + "1111" + "1111" + "1111"     # documented test card
TEST_CARD_SPACED = "4111" + " 1111" + " 1111" + " 1111"
JWT = ("eyJ" + "hbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" + "."
       + "eyJzdWIiOiIxMjM0NTY3ODkwIn0" + "."
       + "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVadQssw5c")
SSN = "219" + "-09-" + "9999"
