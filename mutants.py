"""Mutation check: remove each defense in a scratch copy, the matching tests must go RED.
A control copy must pass first. A mutant that hangs past TIMEOUT counts as killed.
Usage: python3 mutants.py [repo_dir]   (default: the directory holding this file)"""
import pathlib, shutil, subprocess, sys, tempfile
ROOT = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else pathlib.Path(__file__).resolve().parent
TIMEOUT = 30
P = "tests/test_proof.py"
H = "tests/test_hostile.py"
V = "tests/test_v2.py"
K = "tests/test_cascade.py"
S = "scanner.py"
# (name, file, text to remove, text to put in, test file that must fail)
MUTANTS = [
    ("limits: oversize input is scanned", S, "        if len(data) > MAX_BYTES:", "        if False:", P),
    ("limits: the size cap raised a thousandfold", S, "MAX_BYTES = 1 << 20", "MAX_BYTES = 1 << 30", P),
    ("limits: binary input is scanned", S, '        if "\\x00" in text:', "        if False:", H),
    ("fail closed: the error verdict is PASS", S, 'FAIL_VERDICT = "BLOCK"', 'FAIL_VERDICT = "PASS"', P),
    ("unicode: hidden tag characters are not found", S, "TAG_CHARS = range(0xE0000, 0xE0080)", "TAG_CHARS = range(0xE0000, 0xE0000)", P),
    ("unicode: isolate controls are not bidi", S, " | frozenset(range(0x2066, 0x206A))", "", P),
    ("unicode: the zero width space is allowed", S, "ZERO_WIDTH = frozenset({0x200B, 0x200C", "ZERO_WIDTH = frozenset({0x200C", P),
    ("override: new instructions is not matched", S, '    r"\\bnew\\s+instructions?\\s*:",\n', "", P),
    ("override: bracket role markers are not matched", S, '    (r"\\[/?(?:INST|SYS|SYSTEM)\\]|<</?SYS>>", re.I),\n', "", P),
    ("override: a fetch command is not matched", S, '    r"\\b(?:curl|wget)\\s+https?://",\n', "", P),
    ("exfil: encoded template slots are not matched", S, 'SLOT_RE = re.compile(r"\\{\\{|\\$\\{|%7B%7B|%24%7B", re.I)', 'SLOT_RE = re.compile(r"\\{\\{|\\$\\{", re.I)', P),
    ("exfil: encoded text in a URL is not decoded", S, "            if d is not None and _looks_like_text(d):", "            if False:", P),
    ("exfil: an image with encoded text is only quarantined", S, '"BLOCK" if is_image else "QUARANTINE"', '"QUARANTINE"', P),
    ("homoglyph: a non-ASCII URL host is accepted", S, "        if any(ord(c) > 127 for c in m.group(1)):", "        if False:", P),
    ("homoglyph: the mixed token minimum raised tenfold", S, "_mixed(t.group(), 3)", "_mixed(t.group(), 30)", P),
    ("homoglyph: Greek letters are not look-alikes", S, 'CONFUSABLE_SCRIPTS = ("CYRILLIC", "GREEK")', 'CONFUSABLE_SCRIPTS = ("CYRILLIC",)', P),
    ("v2: the canonical detectors are not run", S, "detect_canonical, detect_encoded_v2):", "detect_canonical):", V),
    ("v2: extra confusable letters are not folded", S, "    n = n.translate(CONFUSABLES_V2)", "    n = n", V),
    ("v2: split letters are not joined", S, "    n, idx, touched = _join_letter_runs(n, idx, touched)\n", "", V),
    ("v2: punctuation inside words is kept", S, "    return _strip_inword_punct(n, idx, touched)", "    return n, idx, touched", V),
    ("v2: percent encoding needs thirty groups", S, 'if len(re.findall(r"%[0-9A-Fa-f]{2}", tok)) < 3:', 'if len(re.findall(r"%[0-9A-Fa-f]{2}", tok)) < 30:', V),
    ("v2: hex dumps are not decoded", S, "for regex, decode in ((TOKEN, _decode_percent), (HEX_TEXT_RUN, _decode_hex_text)):", "for regex, decode in ((TOKEN, _decode_percent),):", V),
    ("v2: extra invisible characters are kept", S, "{0x34F, 0x61C, 0x115F", "{0x115F", V),
    ("report: findings are not ordered by severity", S, '        found.sort(key=lambda f: (f["severity"] != "BLOCK", f["offset"]))\n', "", P),
    ("cascade: windows do not overlap", S, "        start = end - overlap", "        start = end", H),
    ("cli: a blocked file exits 0", S, 'worst = max(worst, {"PASS": 0, "QUARANTINE": 1, "BLOCK": 2}[v["verdict"]])', "worst = 0", P),
]


def pytest_rc(tree, test):
    try:
        r = subprocess.run([sys.executable, "-m", "pytest", "-q", "-x", "-p", "no:cacheprovider", test],
                           cwd=tree, capture_output=True, timeout=TIMEOUT,
                           env={"PYTHONDONTWRITEBYTECODE": "1", "PATH": "/usr/bin:/bin"})
    except subprocess.TimeoutExpired:
        return 124                                      # a mutant that hangs the tests is caught
    return r.returncode


def fresh(tmp, name):
    dst = pathlib.Path(tmp) / name
    shutil.copytree(ROOT, dst, ignore=shutil.ignore_patterns(".git", "__pycache__", ".pytest_cache"))
    return dst


def main():
    killed = 0
    tests = sorted({m[4] for m in MUTANTS})
    with tempfile.TemporaryDirectory() as tmp:
        for t in tests:
            if pytest_rc(fresh(tmp, "control-" + pathlib.Path(t).stem), t) != 0:
                print(f"control FAIL {t}"); return 1
        print(f"control {len(tests)}/{len(tests)} test files pass unmodified")
        for i, (name, f, old, new, test) in enumerate(MUTANTS):
            tree = fresh(tmp, f"m{i}")
            src = (tree / f).read_text()
            if src.count(old) != 1:
                print(f"mutant {name}: pattern matched {src.count(old)} times, want 1"); return 1
            (tree / f).write_text(src.replace(old, new))
            red = pytest_rc(tree, test) != 0
            killed += red
            print(f"{'RED ' if red else 'LIVE'} {name}")
    print(f"mutants killed {killed}/{len(MUTANTS)}")
    return 0 if killed == len(MUTANTS) else 1


if __name__ == "__main__":
    sys.exit(main())
