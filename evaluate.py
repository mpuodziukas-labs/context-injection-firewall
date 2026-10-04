import json
import pathlib
import tempfile

import scanner

HERE = pathlib.Path(__file__).parent
ORDER = ["invisible-unicode", "instruction-override", "exfil-beacon", "homoglyph", "encoded-payload", "fail-closed"]


def rows():
    return [json.loads(l) for l in (HERE / "cases.jsonl").read_text().splitlines() if l]


def corpus():
    return sorted(p for p in (HERE / "corpus" / "benign").iterdir() if p.is_file())


def run_case(case, tmp):
    """Run one planted case through the scanner and return its verdict."""
    if "text" in case:
        return scanner.scan_input(case["text"].encode("utf-8"), case["id"])
    if "bytes_hex" in case:
        return scanner.scan_input(bytes.fromhex(case["bytes_hex"]), case["id"])
    if "pad" in case:
        return scanner.scan_input(b"a" * case["pad"], case["id"])
    if "path" in case:
        return scanner.scan_path(str(pathlib.Path(tmp) / case["path"]))
    return scanner.scan_input(12345, case["id"])  # wrong type: the scanner must fail closed


def caught(case, verdict):
    return verdict["verdict"] == case["expect"] and any(f["rule"] == case["rule"] for f in verdict["findings"])


def results():
    out = {}
    with tempfile.TemporaryDirectory() as tmp:
        for c in rows():
            out.setdefault(c["class"], []).append(caught(c, run_case(c, tmp)))
    files = corpus()
    benign = [scanner.scan_path(str(p))["verdict"] == "PASS" for p in files]
    lines = ["| attack class | caught |", "|---|---|"]
    for cls in ORDER:
        r = out.get(cls, [])
        lines.append(f"| {cls} | {sum(r)}/{len(r)} |")
    lines += ["", "| benign corpus | passed |", "|---|---|", f"| files with no attack | {sum(benign)}/{len(benign)} |", ""]
    n = sum(len(v) for v in out.values())
    lines.append(f"attacks caught {sum(sum(v) for v in out.values())}/{n}, benign passed {sum(benign)}/{len(benign)}")
    return "\n".join(lines)


if __name__ == "__main__":
    print(results())
