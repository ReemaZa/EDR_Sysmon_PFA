
import os
from sigma.collection import SigmaCollection

ROOT_FOLDER = r".\sigma_ogic\rules\windows"

def extract_attack_tags(rule):
    techniques, tactics = [], []
    for tag in rule.tags:
        t = str(tag)
        if t.startswith("attack.t"):
            techniques.append(t)
        elif t.startswith("attack."):
            tactics.append(t)
    return techniques, tactics

total = 0
no_attack = 0

for dirpath, _, filenames in os.walk(ROOT_FOLDER):
    for filename in filenames:
        if not filename.endswith((".yml", ".yaml")):
            continue
        file_path = os.path.join(dirpath, filename)
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                ruleset = SigmaCollection.from_yaml(yaml_str=f.read())
            for rule in ruleset:
                total += 1
                techniques, tactics = extract_attack_tags(rule)
                if not techniques:
                    no_attack += 1
                    print(f"  [{no_attack}] {rule.title}")
                    print(f"       {file_path}")
        except Exception:
            pass

print(f"\nTotal rules     : {total}")
print(f"No ATT&CK tags  : {no_attack}")
print(f"Have ATT&CK tags: {total - no_attack}")
