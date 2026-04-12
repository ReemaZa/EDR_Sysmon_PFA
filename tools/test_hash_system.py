"""
EDR L1 Engine - Integration Test
Tests the 3-step detection logic: Whitelist -> Local DB -> API
"""
import sys
from pathlib import Path

# --- Configuration du chemin racine ---
root_path = Path(__file__).resolve().parent.parent
if str(root_path) not in sys.path:
    sys.path.insert(0, str(root_path))

from src.detection.l1_hash_check.l1_hash_reputation import HashReputationEngine
from src.core.pipeline import ThreatLevel

def run_comprehensive_test():
    print("="*70)
    print("🚀 EDR L1 HASH REPUTATION - COMPREHENSIVE TEST")
    print("="*70)

    # 1. Initialisation de l'engin
    # L'engin va se connecter automatiquement à data/malware_intelligence.db
    print("\n[STEP 1] Initializing Engine...")
    engine = HashReputationEngine()

    # --- CAS 1 : LE WHITELISTING (Doit être ignoré) ---
    # Hash de Google Chrome Update que tu as ajouté
    chrome_hash = "E0B1A250229E72BEFE723D9D413DA5086E41EA7CC0876F5431386651A54213BA"
    print(f"\n[STEP 2] Testing Whitelist (Trusted File)...")
    whitelist_event = {
        'event_id': 1,
        'hashes': {'sha256': chrome_hash}
    }
    
    result = engine.check_event(whitelist_event)
    if result is None:
        print(f"   ✅ PASS: Trusted hash {chrome_hash[:10]}... ignored (Whitelisted)")
    else:
        print(f"   ❌ FAIL: Whitelisted hash detected as {result.threat_level.name}!")

    # --- CAS 2 : TABLE MALWAREBAZAAR LOCALE (Détection directe) ---
    # Le hash que tu as fourni (d5ba31...)
    local_malware_hash = "c5057968de7509411ed6015175268d2f5737f0691c5fda3d33ef480b27e46108 "
    print(f"\n[STEP 3] Testing Local Malware Database...")
    local_malware_event = {
        'event_id': 1,
        'hashes': {'sha256': local_malware_hash}
    }

    result = engine.check_event(local_malware_event)
    print(result)
    if result and result.threat_level == ThreatLevel.CRITICAL:
        print(f"   ✅ PASS: Local malware detected!")
        print(f"      Source: {result.metadata.get('source')}")
        print(f"      Threat: {result.threat_level.name}")
    else:
        print(f"   ❌ FAIL: Local malware hash was NOT detected!")

    # --- CAS 3 : MALWAREBAZAAR API (Appel distant) ---
    # Utilisons un hash malveillant connu (Emotet) qui n'est peut-être pas dans ta table locale
    # Hash: 44d88612fea8a8f36de82e1278abb02f (MD5 de test)
    api_malware_hash = "2b0d8c8e86dd372b44b99f8be4e4a7cbbfe5ce78bc10b714fc0735c15b7ddb32"
    print(f"\n[STEP 4] Testing MalwareBazaar API...")
    api_event = {
        'event_id': 1,
        'hashes': {'sha256': api_malware_hash}
    }

    result = engine.check_event(api_event)
    if result:
        print(f"   ✅ PASS: Malware detected via API!")
        print(f"      Source: {result.metadata.get('source')}")
    else:
        # Note: Si l'API est désactivée dans ta config, ceci est un comportement normal
        print(f"   ⚠️ INFO: No API detection (Check if API is enabled and key is valid)")

    # --- CAS 4 : FICHIER PROPRE (Inconnu) ---
    print("\n[STEP 5] Testing Clean/Unknown File...")
    clean_event = {
        'event_id': 1,
        'hashes': {'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'}
    }
    result = engine.check_event(clean_event)
    if result is None:
        print("    PASS: unknow file.")
    else:
        print("   ❌ FAIL: False positive detected!")

    # 6. Statistiques finales
    print("\n" + "="*70)
    print("📊 FINAL ENGINE STATISTICS")
    print("="*70)
    stats = engine.get_stats()
    for key, value in stats.items():
        print(f"   {key.replace('_', ' ').title()}: {value}")
    
    print("\n✅ INTEGRATION TESTS COMPLETED")
    print("="*70)

if __name__ == "__main__":
    run_comprehensive_test()