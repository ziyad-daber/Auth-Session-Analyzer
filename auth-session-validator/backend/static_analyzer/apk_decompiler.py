"""
static_analyzer/apk_decompiler.py
─────────────────────────────────
Décompilation automatique d'un APK via jadx.
"""

import subprocess
import os
import sys
from pathlib import Path

# Import config depuis le dossier parent
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import JADX_PATH, JADX_LINUX, SCAN_TIMEOUT


def get_jadx_path() -> str:
    """Retourne le chemin vers jadx selon l'OS."""
    if sys.platform == "win32":
        return JADX_PATH
    return JADX_LINUX


def decompile_apk(apk_path: str, output_dir: str) -> str:
    """
    Décompile un APK avec jadx.

    Args:
        apk_path:   Chemin absolu vers le fichier .apk
        output_dir: Dossier de sortie pour les fichiers décompilés

    Returns:
        output_dir si succès

    Raises:
        FileNotFoundError: si l'APK n'existe pas
        RuntimeError:      si jadx échoue
    """
    # TODO: vérifier que jadx est installé
    # TODO: lancer jadx -d output_dir apk_path
    # TODO: vérifier que la décompilation a réussi (dossier non vide)
    # TODO: retourner le chemin du dossier décompilé
    raise NotImplementedError("apk_decompiler.py — à implémenter")


def extract_manifest(decompiled_dir: str) -> str:
    """
    Trouve et retourne le chemin vers AndroidManifest.xml.

    Args:
        decompiled_dir: Dossier de sortie jadx

    Returns:
        Chemin absolu vers AndroidManifest.xml
    """
    # TODO: parcourir decompiled_dir pour trouver AndroidManifest.xml
    raise NotImplementedError("extract_manifest — à implémenter")


def get_apk_info(apk_path: str) -> dict:
    """
    Extrait les métadonnées de base d'un APK (package name, version, etc.)

    Returns:
        {"package": str, "version": str, "min_sdk": int, "target_sdk": int}
    """
    # TODO: utiliser androguard ou aapt pour lire les métadonnées
    raise NotImplementedError("get_apk_info — à implémenter")
