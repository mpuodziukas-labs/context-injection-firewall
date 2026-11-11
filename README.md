# context-injection-firewall

Proves: planted hidden instructions in text an agent loads are stopped before they reach the agent. Verify in 60s: python3 evaluate.py

Where this fits: OWASP LLM Top 10 2025 LLM01 Prompt Injection; NIST AI RMF function MANAGE. Sources in SOURCES.md.

A coding agent reads repo files, web pages and tool output as context. One planted line in any of them can take over the agent, and nobody sees it because the line is invisible, encoded or dressed up as data. The team that owns the repository and the credentials pays for it, through a leaked key, a poisoned commit or a command nobody typed.

## Ticket

| Field | Value |
|---|---|
| Ticket | context-injection-firewall 2026-10-25 |
| Status | LIVE |
| Severity of a false pass | A planted hidden instruction in a repo file, web text or tool output reaches the agent because the gate printed all-N/N, and the agent acts on a command nobody typed. |
| Scope (in) | A pattern scan of text before it enters agent context, over six attack classes (invisible-unicode, instruction-override, exfil-beacon, homoglyph, encoded-payload, fail-closed) and a benign corpus that must pass. |
| Out of scope | Semantic paraphrase, text inside images and binary formats, non-English instructions, instructions split across inputs and any agent behaviour (see Limitations). |
| Owner | Michael Puodziukas, michael@puodziukas.dev |
| Opened | 2026-10-04 |
| Last verified | 2026-10-25, `attacks caught 49/49, benign passed 16/16` |
| Oracle | `python3 evaluate.py`, last line `attacks caught 49/49, benign passed 16/16`; `python3 mutants.py`, last line `mutants killed 26/26` |
| Dependencies | Runtime: Python 3 standard library only for the default scan. Optional stage 2 (`--cascade`): onnxruntime, tokenizers and numpy, plus model files that are not in the repo. Test: pytest. |
| Supported platforms | macOS (both oracles measured here, rc=0); Linux through the ubuntu-latest runner in .github/workflows/ci.yml (not measured here). |

## Quick start

```bash
python3 evaluate.py
python3 mutants.py
```

## Run it (60s)

```
python3 -m pip install pytest
python3 evaluate.py
python3 -m pytest -q
```

`python3 evaluate.py` printed:

```
| attack class | caught |
|---|---|
| invisible-unicode | 10/10 |
| instruction-override | 14/14 |
| exfil-beacon | 8/8 |
| homoglyph | 6/6 |
| encoded-payload | 5/5 |
| fail-closed | 6/6 |

| benign corpus | passed |
|---|---|
| files with no attack | 16/16 |

attacks caught 49/49, benign passed 16/16
```

`python3 -m pytest -q` prints a passed count with no failures. To scan your own files: `python3 scanner.py FILE...` prints one JSON verdict per file and exits 0 for all PASS, 1 for QUARANTINE, 2 for BLOCK.

## What the scanner returns

The scanner reads text before it enters agent context and returns one JSON object per input: `input`, `verdict` (PASS, QUARANTINE or BLOCK), `reason` (the rule of the first finding), `offset` (a byte offset into the input) and `findings`. A finding holds `rule`, `severity`, `offset` and a short `detail`. The detail describes the finding and never repeats the matched text. BLOCK outranks QUARANTINE, and findings are listed in offset order within a severity.

## What each planted RED case proves

Every row of the table is one attack class. Each planted case in cases.jsonl must get the verdict and rule it is labeled with, and the tests check that the reported byte offset is where the attack starts. The cases use JSON escapes, so the invisible characters are visible in the file.

- invisible-unicode: tag characters U+E0000 to U+E007F that hide a whole sentence (u-tag-hidden-instruction, u-tag-short, u-tag-cancel) are BLOCK, and the hidden sentence is decoded and checked too. Bidirectional overrides, embeddings and isolates, the Trojan Source class (u-bidi-override, u-bidi-isolate, u-bidi-embedding), are BLOCK. Zero-width characters, a word joiner and a byte order mark inside a file (u-zero-width-space, u-zero-width-joiner-ascii, u-word-joiner, u-bom-midfile) are QUARANTINE. A joiner between two emoji is allowed.
- instruction-override: "ignore previous instructions" and its variants in data are BLOCK, including mixed case, extra whitespace, full-width letters, a zero-width character inside a word and a Cyrillic letter standing in for a Latin one (o-ignore-previous, o-disregard, o-spaced-case, o-fullwidth, o-zwsp-split, o-homoglyph-override, o-new-instructions, o-reveal-system-prompt). Spoofed role markers and fake tool-result blocks (o-role-im-start, o-role-system-tag, o-role-bracket-inst, o-role-line-prefix, o-fake-tool-result, o-fake-function-results) are BLOCK.
- exfil-beacon: a markdown image, markdown link or HTML image whose URL carries a template slot such as double braces or a dollar-brace placeholder is BLOCK, in plain or percent-encoded form (x-image-slot, x-image-dollar-slot, x-link-slot, x-html-img-slot, x-encoded-slot). An image whose query holds base64 or hex that decodes to readable text is BLOCK (x-image-base64-query, x-image-hex-query). The same in a plain link is QUARANTINE (x-link-base64-fragment).
- homoglyph: Cyrillic or Greek letters inside a command in a shell code block or a prompt line are BLOCK (h-cyrillic-in-shell, h-greek-in-shell, h-prompt-line). Non-ASCII letters in a URL host are BLOCK (h-cyrillic-host, h-greek-host-md-link). A word that mixes Latin letters with look-alike letters is QUARANTINE (h-mixed-script-prose).
- encoded-payload: a long base64 or hex run that decodes to an instruction is BLOCK, including a run encoded twice and the URL-safe alphabet (e-base64-instruction, e-base64-curl, e-hex-instruction, e-double-base64, e-urlsafe-base64).
- fail-closed: bytes that are not valid UTF-8, a truncated UTF-8 sequence, a missing file, a directory, input larger than 1 MiB and an input of the wrong type are all BLOCK, never PASS (f-undecodable-bytes, f-truncated-utf8, f-missing-file, f-directory-path, f-oversize, f-wrong-type). The tests also make a detector raise and require BLOCK.

The benign corpus is 16 files in corpus/benign: a README with badges, pinned links and a bug-report block, a contributing guide, Python, JavaScript, shell, YAML and JSON files, a changelog, an HTML page, a CSV file, a Makefile, a tool log, scraped page text and a note with Greek, Russian, French, Japanese and emoji text. They are written to look like real project files and to sit close to the attack rules: an embedded PNG in base64, a package integrity hash, sha256 digests, a commit hash in a URL, a link template with braces in the path, "System: Linux" in a bug template and a Russian comment in a shell script. All 16 must PASS.

The tests also break the scanner on purpose and require the table to change each time. Each mutant removes one defense: tag characters, bidi characters, zero-width characters, the override patterns, the role patterns, the template slot check, the readable-text check for blobs, the decoder, the confusable scripts, the confusable fold, the normalization step, the fail-closed verdict and the size cap.

## v2 canonicalization

Branch v2-normalize adds a canonical copy of the input that is scanned next to the raw input. The verdict is the stricter of the two, and every finding offset is a byte offset into the raw input. The CLI contract and the JSON verdict are unchanged.

The canonical copy is built in this order:

1. Drop extra invisible characters (combining grapheme joiner, Hangul fillers, left-to-right and right-to-left marks, invisible math operators, variation selectors) without a finding. The existing zero-width, bidi and tag findings stay as they were.
2. Decode one level of percent-encoding, `\xNN` escapes, `0xNN` values and spaced hex pairs, when the decoded text is printable.
3. NFKC, casefold and the v1 confusable fold, then a second confusable table from TR39 for Latin, Cyrillic and Greek look-alikes.
4. Join runs of four or more single letters split by spaces or punctuation, then drop punctuation between letters inside a word.
5. Match the same override and role rules on the canonical text. Four override rules also run with optional whitespace, but only where a join happened in step 4.
6. Base64 runs of 8 or more characters are decoded and the decoded text is canonicalized and scanned.

Tests: cases_v2.jsonl holds 26 synthetic attacks (invisible, homoglyph, spacing, encoded, role) and corpus_v2 holds 8 benign controls close to those rules. tests/test_v2.py has one mutant per step. RED-RUN-V2.txt is the run made before the code existed.

Measured, not tuned, with a harness outside this repo. The v1 and v2 rows below are not reproducible from a committed command yet: nothing in this repo prints them. The harness command was `GUARD_ROOT=<folder with v1 or v2 firewall plus the other two guards> python3 evaluate.py` in guard-blind-evals. No case file, miss file or prediction file was read to design a rule.

| set | version | TP | FP | TN | FN | precision [95% CI] | recall [95% CI] |
|---|---|---|---|---|---|---|---|
| in-house held-out (47 attacks, 52 benign) | v1 | 18 | 2 | 50 | 29 | 0.90 [0.70, 0.97] | 0.38 [0.26, 0.53] |
| in-house held-out (47 attacks, 52 benign) | v2 | 20 | 2 | 50 | 27 | 0.91 [0.72, 0.97] | 0.43 [0.30, 0.57] |
| deepset/prompt-injections sample (188 attacks, 312 benign) | v1 | 10 | 2 | 310 | 178 | 0.83 [0.55, 0.95] | 0.05 [0.03, 0.10] |
| deepset/prompt-injections sample (188 attacks, 312 benign) | v2 | 10 | 2 | 310 | 178 | 0.83 [0.55, 0.95] | 0.05 [0.03, 0.10] |

False positives on the benign corpus in this repo: 0 of 16 before and 0 of 16 after. The 8 v2 benign controls: 0 of 8 before and 0 of 8 after. pytest: 128 passed before, 202 passed after. Current suite, from `python -m pytest -q` on this tree: 229 passed, 28 skipped (the skips are the stage-2 tests that need classifier weights, which are not in the repo).

The intervals overlap on both sets, so the in-house gain of 2 true positives is not a proven change in recall, and the public sample shows no change.

Limitations: semantic paraphrase is still out of reach for a pattern scanner. The public sample is mostly natural-language and non-English instructions, and canonicalization does not touch those.

## v3 cascade

`python3 scanner.py --cascade FILE` adds stage 2 after the pattern scanner. A stage-1 BLOCK ends the run. Otherwise a small classifier reads the text and the stricter verdict wins. The default run is unchanged, and the JSON gains one field, `stage` (1 or 2), only under `--cascade`. A classifier hit is QUARANTINE, not BLOCK, because a classifier is a probability.

- Model: protectai/deberta-v3-base-prompt-injection-v2, Apache-2.0, 184,423,682 parameters, ONNX on CPU (onnxruntime, at most 4 threads). It is not in this repo. Download the `onnx/` files into `models/protectai-deberta-v3-pi-v2/onnx/` and check them against `models.lock` (model.onnx sha256 f0ea7f23...228c, tokenizer.json sha256 752fe5f0...ff2f). Tests never download. Keep the files outside the repo tree and set `CASCADE_MODEL_DIR` to the `onnx/` folder, because the publish gate scans every file under the tree, including a third-party vocabulary file.
- Fail closed: weights missing, sha256 mismatch, load or run error, or input needing more than 8 windows of 510 tokens is QUARANTINE, never PASS. Text is tokenized once without truncation and scored in overlapping windows of 508 tokens with a 128-token overlap; the last window must end at the last token, and the highest score counts. More than 8 windows (about 3,100 tokens) is `classifier-oversize`, QUARANTINE. A `models.lock` without a pin for both files is QUARANTINE, and the bytes that are hashed are the bytes that are loaded.
- Threshold: the model card default, P(injection) > 0.5. Not tuned. My own 23-row synthetic dev set (`cascade_dev.jsonl`: 6 English paraphrases, 9 attacks in Spanish, German and French, 8 benign) was written before any measurement. It does not separate the classes at any threshold, so the default stays.
- Training data, from the card: natolambert/xstest-v2-copy, VMware/open-instruct, alespalla/chatbot_instruction_prompts, HuggingFaceH4/grok-conversation-harmless, Harelix/Prompt-Injection-Mixed-Techniques-2024, OpenSafetyLab/Salad-Data, jackhhao/jailbreak-classification. deepset/prompt-injections is not listed, so the deepset number is not labelled contaminated. The card also says some injections were crafted from papers, competitions and community feedback, so overlap cannot be ruled out from the card. The card says the model is English only and gives no per-language numbers.
- Considered and not used: Llama Prompt-Guard-2 22M and 86M (gated, Llama license).

Measured once with `guard-blind-evals/evaluate.py` on temp copies of the three guards, the firewall run with `--cascade`. The harness has no `--cascade` flag, so every cascade number in this section (the table, the 17 of 52 false positives, and the p50 22.5 ms, p95 29.3 ms, max 33.1 ms latency) is not reproducible from a committed command yet. They were measured on the code before the 2026-10-04 window fix, so they describe the old truncating stage 2 and are historical. No tuning after.

| set | TP | FP | TN | FN | precision [95% CI] | recall [95% CI] |
|---|---|---|---|---|---|---|
| in-house blind, v2 alone | 20 | 2 | | | 0.91 [0.72, 0.97] | 0.43 [0.30, 0.57] |
| in-house blind, v3 cascade | 45 | 17 | 35 | 2 | 0.73 [0.60, 0.82] | 0.96 [0.86, 0.99] |
| deepset sample (188 attacks, 312 benign), v2 alone | 10 | 2 | | 178 | 0.83 [0.55, 0.95] | 0.05 [0.03, 0.10] |
| deepset sample, v3 cascade | 86 | 5 | 307 | 102 | 0.95 [0.88, 0.98] | 0.46 [0.39, 0.53] |

- Benign false positives on the in-house blind set: 17 of 52. On this repo's benign corpus, 6 of 24 files are flagged (command: `python3 scanner.py --cascade` on every file under corpus/benign and corpus_v2, 6 of 24 not PASS on 2026-10-04) (documentation, JSON, CSV, a hex dump, identifiers). The goal was at most 1 of 24, so it is not met. Cascade precision 0.73 has a lower bound of 0.60, below the v2 lower bound of 0.72, so that goal is not met either.
- Stage-2 latency over 500 inputs (the 23 dev rows repeated, short texts, warm model, this Mac, CPU): p50 22.5 ms, p95 29.3 ms, max 33.1 ms. Goal of 50 ms met. Longer inputs cost more per window. Process start with hash check and model load is about 1.5 s per CLI call.
- Recall 0.96 on the in-house set meets the 0.90 goal. Recall on the deepset sample is 0.46 and misses the goal: the sample is largely non-English and the model is English only. The in-house miss list is not published here because the blind-eval rules keep case and miss files unread.

Limitations of v3: the benign false-positive rate is high for documentation, structured data and instruction-style text such as setup steps, so a reviewer will see many QUARANTINE verdicts. The classifier has no per-language numbers from its card, and my dev set is 15 attacks. Windows and the 8-window cap mean a file over about 3,100 tokens (roughly 13,000 characters of prose) is quarantined, not judged. Turkish is a known miss: the English-only classifier scores a Turkish paraphrase of an override at 0.005 and the scanner passes it (planted as a strict xfail in tests/test_hostile.py). No keyword list for one language was added. Only a stage-1 BLOCK is final. The in-house blind set was already used to evaluate v1 and v2, so it is not fresh. Stage 3 (taint flow at tool sinks) is not part of this change.

## Normal procedure

1. From the repo root run `python3 evaluate.py`. It prints two tables and a summary line, and exits with code zero when every count is N/N and the benign files all pass, code one otherwise.
2. Read the rows. Each attack class row counts the planted cases in `cases.jsonl` that got exactly the labeled verdict and rule. The benign row counts the files in `corpus/benign` that got the verdict PASS. The summary line adds the attack rows and repeats the benign count.
3. PASS means every row reads N/N, exactly as quoted here:

```text
| attack class | caught |
|---|---|
| invisible-unicode | 10/10 |
| instruction-override | 14/14 |
| exfil-beacon | 8/8 |
| homoglyph | 6/6 |
| encoded-payload | 5/5 |
| fail-closed | 6/6 |

| benign corpus | passed |
|---|---|
| files with no attack | 16/16 |

attacks caught 49/49, benign passed 16/16
```

4. Run `python3 mutants.py` to prove the tests can fail. It copies the repo to a temporary directory, applies each planted edit to `scanner.py`, and requires the matching test file to go red. PASS ends with `mutants killed 26/26`.

Scan a file yourself: `python3 scanner.py FILE` (exit 0 PASS, 1 QUARANTINE, 2 BLOCK).

## Abnormal procedure

| Symptom | Cause | Action | Oracle |
|---|---|---|---|
| `evaluate.py` exits with code one and an attack class row is short | A planted case in `cases.jsonl` no longer gets its labeled verdict and rule, or a detector changed | Put the case text in a file, run `python3 scanner.py FILE` on it and compare the verdict and the rule with the label | `python3 evaluate.py` |
| The benign row is short | A file in `corpus/benign` now trips a rule | Run `python3 scanner.py` on each benign file and read the `reason` of the one that is not PASS | `python3 evaluate.py` |
| `mutants.py` prints a LIVE line | A defense edit that the tests do not detect, which is a gap in the test files | Add or tighten a test until that line prints RED | `python3 mutants.py` |
| `mutants.py` prints `control FAIL` or `pattern matched` | The unmodified tests fail in the copy (for example pytest is missing), or the source line a mutant targets has moved | Run `python3 -m pip install pytest`, or update the pattern in `mutants.py` | `python3 mutants.py` |
| `python3 scanner.py --cascade FILE` returns QUARANTINE on every file | The model files are missing, or their sha256 does not match `models.lock` (stage 2 fails closed) | Download the model files as described in the v3 cascade section and set `CASCADE_MODEL_DIR` | `python3 scanner.py --cascade FILE` |

## Emergency procedure

The gate printed PASS but a planted instruction still reached the agent: a file the scanner passed carried a hidden or encoded instruction.

1. Freeze: stop loading new files into agent context on the strength of this gate, and record the repo commit and the exact file that got through.
2. Replay: run `python3 scanner.py FILE` on the offending file. If it exits with code zero, add the file text as a single-attack case in `cases.jsonl` with its class, verdict and rule, fix or add the detector in `scanner.py`, and add a mutant to `mutants.py`. Then run `python3 evaluate.py` and `python3 mutants.py` and expect every count N/N.
3. Tell: the owner (michael@puodziukas.dev) and every team that loads context through this gate. Name the missing rule and the Limitations item that covers it.

## Honesty

This is a small deterministic scanner, not a product, and it is a pattern check, not a defense in depth: it reads text and returns a verdict, and it does not contain an agent that ignores the verdict. The cases in cases.jsonl and the files in corpus/benign are synthetic and written for this repo. I did not test it against a real agent, real web pages or a real repository.

The false positive count on the benign corpus is 0 of 16. That corpus is small and I wrote it, so 0 is the count for these files and not a rate for real repositories. I know of classes that would raise it: a security document that quotes an attack phrase such as "ignore previous instructions" is BLOCK, a Latin word mixed with a Greek or Cyrillic letter in prose is QUARANTINE, a URL host with accented letters is BLOCK, and a role marker such as SYSTEM: in capitals at the start of a line is BLOCK.

## Limitations

- It is a pattern scanner. A new paraphrase of an instruction, such as a request phrased as a polite question or split across several sentences, passes.
- Semantic attacks pass: a README that tells an agent to trust a malicious package in plain, ordinary language has no pattern to match.
- Text inside images, PDFs and other binary formats is not read. A non-UTF-8 file is BLOCK, so binary files are refused, not understood.
- Only base64 and hex are decoded, to two levels. Other encodings, ciphers and compression pass.
- The override and role lists are English and short. Other languages pass.
- Homoglyph checks cover Cyrillic and Greek. Other look-alike scripts and mixed-script words shorter than three Latin letters pass, and inline code in prose is not treated as a shell command.
- It scans one input at a time. An instruction split across two files or two tool calls is not joined.
- Input containing a NUL byte is BLOCK (binary input is refused).
- Input over 1 MiB is BLOCK, which is a size cap and not a judgment about the content.
- The pytest suite and the stage-2 model tests are not part of the evidence below and were not run for this restructuring.

## CI

The workflow in .github/workflows/ci.yml runs `python evaluate.py` and `python -m pytest -q` on push and pull request, with each action pinned to a commit. CI has no model weights, so the stage-2 tests that need the classifier skip there and only the fail-closed and window-arithmetic tests run; the model tests run locally.

## Hostile review 2026-10-04

An adversarial review (RED-RUN-REVIEW.txt) found 23 rows: kill 2, high 6, med 6, pass 9. Fixed 14 of 14 kill, high and med rows, or recorded them honestly; the 9 pass rows needed nothing.

- K1, K1b: stage 2 judged only the first window; now tokenized once, overlapping windows, coverage asserted. Fixed.
- K1c: the 8-window cap never fired; it now counts real windows and 1 MiB prose is `classifier-oversize`. Fixed.
- H1: the long-input test was vacuous; its padding is now proven benign inside the test. Fixed.
- H2: a split at a window edge; the overlap catches it, tested at 5 offsets. Fixed.
- H3: Turkish miss. Recorded in Limitations and as a strict xfail, no principled fix.
- H4, M2: the cascade numbers had no committed command. Labelled "not reproducible"; owner row to add a `--cascade` mode to the harness. M2 now names its command.
- H5: an empty or partial `models.lock` skipped the check. Now QUARANTINE.
- M1: the p95 test is skipped with a printed SKIP when load average exceeds cores and otherwise takes the best of 3 rounds; the 50 ms budget is unchanged. The p95 number is labelled not reproducible.
- M3: CI skips the model tests; stated in the CI section.
- M4: NUL input is BLOCK.
- M5: the hashed bytes are now the loaded bytes (session and tokenizer built from memory).
- M6: the README makes no claim of a third stage; a test pins that.
- F8 (director): lock paths that do not name the pinned files, or a missing tokenizer, are QUARANTINE (tested).

## RED run

red/RED-run.txt holds the run made before the scanner existed: the tests were written first against a stub that passed everything, and every attack test failed.

## Architecture

| Path | Role | Lines |
|---|---|---|
| `scanner.py` | The scanner: detectors, canonicalization, optional stage 2, command line | 568 |
| `evaluate.py` | The oracle: runs every planted case and the benign corpus, prints the tables | 54 |
| `mutants.py` | Mutation check: edits copies of `scanner.py` and requires the matching test file to go red | 81 |
| `cases.jsonl` | Planted attack cases with expected verdict and rule | 49 |
| `cases_v2.jsonl` | Planted attack cases for the canonicalization step | 26 |
| `cascade_dev.jsonl` | Synthetic dev set for the stage-2 threshold | 23 |
| `models.lock` | Pinned sha256 values for the stage-2 model files | 20 |
| `tests/test_proof.py` | Proof tests: table matches output, offsets, verdicts | 152 |
| `tests/test_hostile.py` | Hostile-review tests | 209 |
| `tests/test_v2.py` | Canonicalization tests, one mutant per step | 110 |
| `tests/test_cascade.py` | Stage-2 tests: fail-closed and window arithmetic | 194 |
| `tests/hostile_data.py` | Data used by the hostile-review tests | 21 |
| `corpus/benign/` | Benign files that must PASS | none: directory |
| `corpus_v2/` | Benign controls for the canonicalization step | none: directory |
| `red/RED-run.txt` | Run made before the scanner existed | 116 |

Data flow:

1. `evaluate.py` feeds each case in `cases.jsonl` to `scanner.py` and checks the verdict and the rule against the label.
2. `evaluate.py` scans every file in `corpus/benign` and requires PASS.
3. It prints the tables and the summary line, which is the last line.
4. `mutants.py` edits copies of `scanner.py` and requires the matching test file to go red.

## Test and mutation evidence

Measured on 2026-10-25 on macOS by running both oracles from the repo root. Each exited with code zero (rc=0). Last line of `python3 evaluate.py`:

```text
attacks caught 49/49, benign passed 16/16
```

The last table row that `python3 evaluate.py` printed, before the summary line:

```text
| files with no attack | 16/16 |
```

Last line of `python3 mutants.py`:

```text
mutants killed 26/26
```

## Change log

| Date | Change | Oracle after |
|---|---|---|
| 2026-10-25 | Additive restructuring to the README standard: sections added, no old line altered | `python3 evaluate.py` last line `attacks caught 49/49, benign passed 16/16`; `python3 mutants.py` last line `mutants killed 26/26` |
| 2026-10-04 | First commits (date from the repo git log) | none: no oracle output was recorded for those commits |

## License

MIT, see LICENSE.

Agent verification contract: [AGENTS.md](AGENTS.md)
