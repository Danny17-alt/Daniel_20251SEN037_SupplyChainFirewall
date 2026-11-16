"""
Quality check for the raw OSV / GitHub Advisory JSON files.
Read-only: it never changes a file. It only counts problems.

Run from the repo root:
    python scripts/quality_check.py data/raw

Copy the printed counts into data/dataset_card.md.
"""
import json
import sys
from collections import Counter
from pathlib import Path

root = Path(sys.argv[1] if len(sys.argv) > 1 else "data/raw")
files = sorted(root.rglob("*.json"))

total = 0          # records we could read
unreadable = []    # files that are not valid JSON
ids = Counter()    # to find duplicate advisory ids
cves = Counter()   # to find one CVE used by several advisories

withdrawn = 0
no_alias = 0            # no CVE or other alias
no_cve_alias = 0        # aliases exist but none starts with CVE-
no_severity_vector = 0  # empty "severity" list
no_label = 0            # no database_specific.severity
no_cwe = 0              # no CWE id
no_affected = 0         # nothing in "affected"
no_ranges = 0           # affected entries without a version range
multi_affected = 0      # advisory affects more than one package
no_summary = 0
no_references = 0
bad_published = 0       # published date not like 2024-01-16T21:31:22Z

labels = Counter()
ecosystems = Counter()          # affected-package entries per ecosystem
adv_ecosystems = Counter()      # advisories touching each ecosystem
severity_types = Counter()      # CVSS_V3, CVSS_V4 ...
event_kinds = Counter()         # introduced, fixed, last_affected ...

for f in files:
    try:
        d = json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        unreadable.append(str(f))
        continue
    total += 1
    ids[d.get("id", "")] += 1

    if d.get("withdrawn"):
        withdrawn += 1

    aliases = d.get("aliases") or []
    if not aliases:
        no_alias += 1
    cve_list = [a for a in aliases if a.startswith("CVE-")]
    if aliases and not cve_list:
        no_cve_alias += 1
    for c in cve_list:
        cves[c] += 1

    sev = d.get("severity") or []
    if not sev:
        no_severity_vector += 1
    for s in sev:
        severity_types[s.get("type", "?")] += 1

    ds = d.get("database_specific") or {}
    lab = ds.get("severity")
    if not lab:
        no_label += 1
    else:
        labels[lab] += 1
    if not ds.get("cwe_ids"):
        no_cwe += 1

    aff = d.get("affected") or []
    if not aff:
        no_affected += 1
    if len(aff) > 1:
        multi_affected += 1
    seen = set()
    for a in aff:
        eco = (a.get("package") or {}).get("ecosystem", "?")
        ecosystems[eco] += 1
        seen.add(eco)
        rs = a.get("ranges") or []
        if not rs:
            no_ranges += 1
        for r in rs:
            for e in r.get("events", []):
                for k in e:
                    event_kinds[k] += 1
    for eco in seen:
        adv_ecosystems[eco] += 1

    if not (d.get("summary") or "").strip():
        no_summary += 1
    if not d.get("references"):
        no_references += 1
    p = d.get("published", "")
    if not (len(p) == 20 and p[4] == "-" and p.endswith("Z")):
        bad_published += 1

dup_ids = sum(1 for k, v in ids.items() if v > 1)
cve_shared = sum(1 for k, v in cves.items() if v > 1)

def line(label, n):
    print(f"{label:<55}{n}")

print(f"Folder checked: {root}")
print("-" * 62)
line("JSON files found", len(files))
line("Records read OK", total)
line("Files that are not valid JSON", len(unreadable))
line("Duplicate advisory ids", dup_ids)
print("-" * 62)
line("Withdrawn advisories", withdrawn)
line("No aliases at all", no_alias)
line("Aliases but no CVE id", no_cve_alias)
line("CVE ids used by more than one advisory", cve_shared)
line("No CVSS vector (empty severity list)", no_severity_vector)
line("No severity label (database_specific.severity)", no_label)
line("No CWE id", no_cwe)
line("Empty summary", no_summary)
line("No references", no_references)
line("Published date not in expected format", bad_published)
print("-" * 62)
line("No affected package", no_affected)
line("Affected entries without a version range", no_ranges)
line("Advisories affecting more than one package", multi_affected)
print("-" * 62)
print("Severity labels:", dict(labels))
print("CVSS vector types:", dict(severity_types))
print("Version-range event kinds:", dict(event_kinds))
print("Advisories per ecosystem:", dict(adv_ecosystems.most_common()))
print("Affected entries per ecosystem:", dict(ecosystems.most_common()))
if unreadable:
    print("Unreadable files:", unreadable[:5])
