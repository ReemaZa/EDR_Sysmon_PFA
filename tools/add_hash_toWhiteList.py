from src.detection.l1_hash_check.malware_intelligence_db import MalwareIntelligenceDB

# 1. Setup connection
db = MalwareIntelligenceDB("data/malware_intelligence.db")

# 2. Define your trusted files
trusted_files = [
    {
        "hash": "60C04034A1E21D71588BC3266C9B4F924032AEFE57A764CB3C0F1E545812A1B5", 
        "name": "Internal_HR_App.exe",
        "src": "internal_dev"
    },
    {
        "hash": "E0B1A250229E72BEFE723D9D413DA5086E41EA7CC0876F5431386651A54213BA", 
        "name": "Google Chrome Update",
        "src": "vendor_standard"
    }
]

# 3. Add them
for item in trusted_files:
    db.add_whitelist_hash(
        file_hash=item["hash"],
        product_name=item["name"],
        source=item["src"]
    )