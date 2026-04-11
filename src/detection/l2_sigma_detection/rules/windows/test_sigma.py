import os
from sigma.collection import SigmaCollection
from sigma.rule import SigmaDetection, SigmaDetectionItem

ROOT_FOLDER = r".\sigma\rules\windows"

total = 0
nested = 0
nested_rules = []

def has_nested_detections(rule):
    for detection in rule.detection.detections.values():
        for item in detection.detection_items:
            if isinstance(item, SigmaDetection):
                return True
    return False

for dirpath, dirnames, filenames in os.walk(ROOT_FOLDER):
    for filename in filenames:
        if not filename.endswith((".yml", ".yaml")):
            continue
        file_path = os.path.join(dirpath, filename)
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                yaml_content = f.read()
            ruleset = SigmaCollection.from_yaml(yaml_str=yaml_content, collect_errors=True)
            for rule in ruleset:
                if rule.errors:
                    continue
                total += 1
                if has_nested_detections(rule):
                    nested += 1
                    nested_rules.append((rule.title, file_path))
        except Exception as e:
            print(f"[ERROR] {file_path}: {e}")

print(f"\nTotal valid rules scanned : {total}")
print(f"Rules with nested detections: {nested} ({100*nested/total:.1f}% of total)\n")

print("Sample of affected rules:")
for title, path in nested_rules[:20]:
    print(f"  - {title}")
    print(f"    {path}")