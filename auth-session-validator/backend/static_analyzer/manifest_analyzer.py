"""
static_analyzer/manifest_analyzer.py
───────────────────────────────────
Analyse du fichier AndroidManifest.xml pour détecter les mauvaises configurations.
"""

import xml.etree.ElementTree as ET
import os
from typing import List, Dict, Any

def analyze_manifest(decompiled_dir: str) -> Dict[str, Any]:
    """
    Analyse le Manifest pour les vulnérabilités classiques et extrait le nom du package.
    """
    results = {
        "findings": [],
        "package_name": "unknown.package"
    }
    
    manifest_path = os.path.join(decompiled_dir, "resources", "AndroidManifest.xml")
    
    # Si JADX a mis le manifest à la racine
    if not os.path.exists(manifest_path):
        manifest_path = os.path.join(decompiled_dir, "AndroidManifest.xml")
        
    if not os.path.exists(manifest_path):
        return results

    try:
        tree = ET.parse(manifest_path)
        root = tree.getroot()
        
        # Récupération du nom du package
        results["package_name"] = root.get("package", "unknown.package")
        
        ns = {"android": "http://schemas.android.com/apk/res/android"}
        
        application = root.find("application")
        if application is not None:
            # 1. Debuggable
            debuggable = application.get("{http://schemas.android.com/apk/res/android}debuggable")
            if debuggable == "true":
                results["findings"].append({
                    "type": "Manifest_Debuggable",
                    "severity": "HIGH",
                    "cvss": 7.5,
                    "description": "L'application est en mode debuggable. Un attaquant peut attacher un debugger."
                })
                
            # 2. AllowBackup
            allow_backup = application.get("{http://schemas.android.com/apk/res/android}allowBackup")
            if allow_backup != "false":
                results["findings"].append({
                    "type": "Manifest_AllowBackup",
                    "severity": "MEDIUM",
                    "cvss": 5.0,
                    "description": "L'application autorise la sauvegarde ADB (allowBackup=true). Risque d'extraction de données."
                })

        # 3. Permissions dangereuses
        dangerous_perms = [
            "android.permission.READ_EXTERNAL_STORAGE",
            "android.permission.WRITE_EXTERNAL_STORAGE",
            "android.permission.INTERNET",
        ]
        
        for perm in root.findall("uses-permission"):
            name = perm.get("{http://schemas.android.com/apk/res/android}name")
            if name in dangerous_perms:
                results["findings"].append({
                    "type": "Dangerous_Permission",
                    "severity": "LOW",
                    "cvss": 3.0,
                    "description": f"L'application utilise une permission sensible : {name}"
                })

    except Exception as e:
        print(f"Erreur Manifest : {e}")
        
    return results
