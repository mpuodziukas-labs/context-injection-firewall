# Verifying this repository

Purpose: demonstrates a pre-agent scanner that stops hidden instructions planted in text an agent loads for teams subject to model-risk, audit or change-control review.

Verify: `python3 evaluate.py`

Pass condition: exit code 0 and this exact output line (leading spaces ignored): `attacks caught 49/49, benign passed 16/16`

Scope: synthetic data, fixed seed, offline, under 60 seconds.

Limitations: A pattern scanner: new paraphrases and semantic attacks pass. Text inside images and binary formats is not read. Only base64 and hex are decoded, two levels. Pattern lists are English and short. Homoglyph checks cover Cyrillic and Greek only. One input is scanned at a time, so split instructions are not joined.

Anything else = not verified.
