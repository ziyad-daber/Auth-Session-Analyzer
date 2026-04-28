"""
backend/static_analyzer/storage_scanner.py
Analyse de sécurité du stockage des tokens et données sensibles
"""

import re
import os
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path


class StorageScanner:
    """
    Analyse le stockage des données sensibles dans l'application Android.

    Détecte:
    - Stockage insecure des tokens (SharedPreferences non chiffrés)
    - Tokens/credentials dans Logcat
    - Tokens/credentials dans les URLs
    - Tokens dans les analytics/third-party SDKs
    - Fichiers de stockage non sécurisés
    """

    # Patterns pour SharedPreferences insecure
    SHARED_PREFS_PATTERNS = [
        # SharedPreferences normal (non sécurisé) pour tokens
        r'SharedPreferences.*\.(getString|setString)\s*\(\s*["\']?(token|jwt|access|refresh|session|auth)["\']?',
        r'getSharedPreferences\s*\(\s*["\'].*(?:token|session|auth|cred).*["\']',
        r'\.edit\s*\(\s*\)\s*\.(putString|commit|apply)',
        r'SharedPreferences.*token',
        r'SharedPreferences.*session',
        r'SharedPreferences.*credential',
        # Mode privé mais toujours non chiffré
        r'MODE_PRIVATE.*SharedPreferences',
        r'Context\.MODE_PRIVATE',
    ]

    # Patterns pour EncryptedSharedPreferences (sécurisé)
    ENCRYPTED_PREFS_PATTERNS = [
        r'EncryptedSharedPreferences',
        r'EncryptedSharedPreferences\.create',
        r'Prefs\.encrypted',
        r'MasterKey.*SharedPreferences',
    ]

    # Patterns pour Android Keystore (sécurisé)
    KEYSTORE_PATTERNS = [
        r'AndroidKeyStore',
        r'KeyStore\.getInstance\s*\(\s*["\']AndroidKeyStore["\']',
        r'KeyGenerator.*AndroidKeyStore',
        r'KeyPairGenerator.*AndroidKeyStore',
        r'SecretKey.*AndroidKeyStore',
        r'KeyGenParameterSpec',
        r'setUserAuthenticationRequired',
        r'generateKeyPair\s*\(\s*["\'].*["\']\s*,\s*KeyGenParameterSpec',
    ]

    # Patterns pour fuites dans Logcat
    LOGCAT_LEAK_PATTERNS = [
        r'Log\.(d|e|i|v|w)\s*\(\s*["\'].*["\']\s*,\s*.*(?:token|jwt|auth|session|password|secret|key|credential)',
        r'Log\.(d|e|i|v|w)\s*\(\s*.*,\s*["\'].*(?:token|jwt|auth|session|password|secret|key|credential)',
        r'token.*Log\.',
        r'password.*Log\.',
        r'secret.*Log\.',
        r'Log.*\+\s*(?:token|password|secret|auth)',
        r'Log\..*\+\s*(?:token|password|secret|auth)',
        r'System\.out\.print.*(?:token|password|secret)',
        r'printStackTrace\s*\(\s*\)',  # Peut révéler des données sensibles
    ]

    # Patterns pour tokens dans URLs
    URL_LEAK_PATTERNS = [
        r'https?://[^\s"\'<>]*[?&](?:token|access_token|refresh_token|session|auth|api_key|key|secret)=',
        r'Uri\.parse\s*\(\s*["\'].*[?&](?:token|access_token|session|auth)=',
        r'HttpUrl\.parse\s*\(\s*["\'].*[?&](?:token|access_token|session|auth)=',
        r'@GET\s*\(\s*["\'].*[?&](?:token|access_token|session|auth)=',
        r'@Url.*(?:token|access_token|session|auth)',
        r'queryParameter\s*\(\s*["\'](?:token|access_token|session|auth)',
    ]

    # Patterns pour analytics/third-party SDKs
    ANALYTICS_PATTERNS = [
        # Firebase Analytics
        r'FirebaseAnalytics.*logEvent',
        r'Bundle\.putString\s*\(\s*["\'].*(?:token|auth|session)',
        r'analytics\.logEvent\s*\(\s*["\'].*["\']\s*,\s*Bundle',
        # Crashlytics
        r'FirebaseCrashlytics.*setCustomKey',
        r'Crashlytics\.setCustomKey',
        # Autres analytics
        r'FlurryAgent\.',
        r'AppsFlyerLib\.',
        r'Adjust\.',
    ]

    # Patterns pour stockage fichier insecure
    FILE_STORAGE_PATTERNS = [
        r'openFileOutput\s*\(\s*["\'].*(?:token|session|auth|cred)',
        r'FileOutputStream.*(?:token|session|auth)',
        r'File\.createTempFile\s*\(\s*["\'].*(?:token|session)',
        r'\.writeText\s*\(\s*.*(?:token|session|auth)',
        r'FileWriter.*(?:token|session|auth)',
        r'ObjectOutputStream.*(?:token|session)',
    ]

    # Patterns pour Database insecure
    DATABASE_PATTERNS = [
        r'SQLiteOpenHelper.*(?:token|session|auth|cred)',
        r'RoomDatabase.*(?:token|session|auth)',
        r'@Entity\s*\(\s*tableName\s*=\s*["\'].*(?:token|session|auth)',
        r'ContentValues.*put\s*\(\s*["\'](?:token|password|secret|key)',
        r'db\.insert\s*\(\s*["\'].*(?:user|auth|token)',
        r'@ColumnInfo\s*\(\s*name\s*=\s*["\'].*(?:token|password|secret)',
    ]

    def __init__(self):
        self.findings = []

    def scan_directory(self, source_dir: str) -> List[Dict[str, Any]]:
        """
        Scanne un dossier source pour des vulnérabilités de stockage.

        Args:
            source_dir: Chemin vers le code source décompilé

        Returns:
            Liste des findings
        """
        self.findings = []
        source_path = Path(source_dir)

        if not source_path.exists():
            return self.findings

        # Scanner tous les fichiers Java/Kotlin
        for ext in ["**/*.java", "**/*.kt"]:
            for file_path in source_path.glob(ext):
                self._scan_file(file_path)

        return self.findings

    def _scan_file(self, file_path: Path) -> None:
        """Scanne un fichier individuel."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.split("\n")

            relative_path = str(file_path)

            # SharedPreferences insecure
            self._check_patterns(
                content, lines, relative_path,
                self.SHARED_PREFS_PATTERNS,
                "INSECURE_SHARED_PREFS",
                "Stockage potentiel de tokens/credentials dans SharedPreferences non chiffrés",
                "HIGH",
                "V7.1-2"
            )

            # Vérifier si EncryptedSharedPreferences est utilisé (positif)
            encrypted_usage = self._check_positive_patterns(
                content, self.ENCRYPTED_PREFS_PATTERNS,
                "ENCRYPTED_SHARED_PREFS",
                "Utilisation de EncryptedSharedPreferences (bon)"
            )
            if encrypted_usage:
                self._add_positive_finding(encrypted_usage, file_path)

            # Keystore usage (positif)
            keystore_usage = self._check_positive_patterns(
                content, self.KEYSTORE_PATTERNS,
                "KEYSTORE_USAGE",
                "Utilisation de Android Keystore (bon)"
            )
            if keystore_usage:
                self._add_positive_finding(keystore_usage, file_path)

            # Logcat leaks
            self._check_patterns(
                content, lines, relative_path,
                self.LOGCAT_LEAK_PATTERNS,
                "SENSITIVE_LOG_LEAK",
                "Fuite potentielle de données sensibles dans Logcat",
                "HIGH",
                "V7.3-1"
            )

            # URL leaks
            self._check_patterns(
                content, lines, relative_path,
                self.URL_LEAK_PATTERNS,
                "CREDENTIAL_IN_URL",
                "Token ou credential transmis dans l'URL (query parameter)",
                "CRITICAL",
                "V7.3-2"
            )

            # Analytics SDKs avec données sensibles
            self._check_patterns(
                content, lines, relative_path,
                self.ANALYTICS_PATTERNS,
                "ANALYTICS_SENSITIVE_DATA",
                "Données potentielles envoyées à des SDKs analytics (vérifier le contenu)",
                "MEDIUM",
                "V7.3-1"
            )

            # File storage insecure
            self._check_patterns(
                content, lines, relative_path,
                self.FILE_STORAGE_PATTERNS,
                "INSECURE_FILE_STORAGE",
                "Stockage potentiel de tokens dans des fichiers non sécurisés",
                "HIGH",
                "V7.1-1"
            )

            # Database insecure
            self._check_patterns(
                content, lines, relative_path,
                self.DATABASE_PATTERNS,
                "INSECURE_DATABASE_STORAGE",
                "Stockage potentiel de données sensibles en base de données (vérifier chiffrement)",
                "MEDIUM",
                "V7.1-1"
            )

        except Exception as e:
            pass  # Ignorer les erreurs de lecture

    def _check_patterns(
        self,
        content: str,
        lines: List[str],
        file_path: str,
        patterns: List[str],
        finding_type: str,
        description: str,
        severity: str,
        masvs_ref: str
    ) -> None:
        """Vérifie des patterns et ajoute des findings."""
        for i, line in enumerate(lines, 1):
            for pattern in patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    # Vérifier si c'est dans un commentaire
                    if self._is_comment(line):
                        continue

                    # Vérifier si c'est déjà protégé (ex: EncryptedSharedPreferences)
                    if self._is_protected(content, patterns):
                        continue

                    self.findings.append({
                        "type": finding_type,
                        "severity": severity,
                        "description": description,
                        "file": file_path,
                        "line": i,
                        "snippet": self._get_snippet(line),
                        "owasp": masvs_ref,
                        "impact": self._get_impact(finding_type),
                        "recommendation": self._get_recommendation(finding_type)
                    })
                    return  # Un finding par type par fichier

    def _check_positive_patterns(
        self,
        content: str,
        patterns: List[str],
        finding_type: str,
        description: str
    ) -> Optional[Dict]:
        """Vérifie des patterns positifs (bonnes pratiques)."""
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return {
                    "type": finding_type,
                    "description": description,
                    "severity": "INFO"
                }
        return None

    def _is_comment(self, line: str) -> bool:
        """Vérifie si une ligne est un commentaire."""
        stripped = line.strip()
        return (
            stripped.startswith("//") or
            stripped.startswith("/*") or
            stripped.startswith("*") or
            stripped.startswith("#")
        )

    def _is_protected(self, content: str, patterns: List[str]) -> bool:
        """Vérifie si le code est protégé (ex: utilise EncryptedSharedPreferences)."""
        # Si on trouve EncryptedSharedPreferences dans le même fichier
        if any(p in patterns for p in self.SHARED_PREFS_PATTERNS):
            for enc_pattern in self.ENCRYPTED_PREFS_PATTERNS:
                if re.search(enc_pattern, content, re.IGNORECASE):
                    return True
        return False

    def _get_snippet(self, line: str, max_length: int = 150) -> str:
        """Extrait un snippet de code."""
        stripped = line.strip()
        if len(stripped) > max_length:
            return stripped[:max_length] + "..."
        return stripped

    def _get_impact(self, finding_type: str) -> str:
        """Retourne l'impact d'un type de finding."""
        impacts = {
            "INSECURE_SHARED_PREFS": "Les tokens stockés en clair peuvent être lus par un attaquant avec accès root ou via backup ADB.",
            "SENSITIVE_LOG_LEAK": "Les données sensibles dans Logcat peuvent être lues par d'autres applications avec permission READ_LOGS.",
            "CREDENTIAL_IN_URL": "Les tokens dans les URLs sont exposés dans les logs proxy, history navigateur, et analytics.",
            "ANALYTICS_SENSITIVE_DATA": "Les SDKs analytics peuvent exfiltrer des données sensibles vers des serveurs tiers.",
            "INSECURE_FILE_STORAGE": "Les fichiers non chiffrés peuvent être lus par un attaquant avec accès au filesystem.",
            "INSECURE_DATABASE_STORAGE": "Les bases de données non chiffrées peuvent être extraites via backup ADB ou root access."
        }
        return impacts.get(finding_type, "Risque de sécurité non spécifié.")

    def _get_recommendation(self, finding_type: str) -> str:
        """Retourne une recommandation pour un type de finding."""
        recommendations = {
            "INSECURE_SHARED_PREFS": "Utiliser EncryptedSharedPreferences ou stocker les tokens dans Android Keystore.",
            "SENSITIVE_LOG_LEAK": "Supprimer tous les logs contenant des données sensibles. Utiliser BuildConfig.DEBUG pour les logs de dev uniquement.",
            "CREDENTIAL_IN_URL": "Utiliser les headers Authorization pour les tokens. Ne jamais mettre de credentials dans les query parameters.",
            "ANALYTICS_SENSITIVE_DATA": "Auditer toutes les données envoyées aux SDKs analytics. Désactiver ou filtrer les données sensibles.",
            "INSECURE_FILE_STORAGE": "Chiffrer les fichiers sensibles ou utiliser le stockage sécurisé (EncryptedFile, Keystore).",
            "INSECURE_DATABASE_STORAGE": "Utiliser SQLCipher ou Room avec chiffrement pour les données sensibles."
        }
        return recommendations.get(finding_type, "Revoir l'implémentation de stockage.")

    def _add_positive_finding(self, finding: Dict, file_path: Path) -> None:
        """Ajoute un finding positif (bonne pratique)."""
        finding["file"] = str(file_path)
        finding["severity"] = "INFO"
        # On ne les ajoute pas aux findings négatifs, mais on pourrait les tracker séparément
        pass  # Pour l'instant, on ignore les positifs dans la liste des vulnérabilités

    def analyze_token_storage(
        self,
        tokens: List[Dict],
        source_dir: str
    ) -> Dict[str, Any]:
        """
        Analyse spécifique du stockage des tokens.

        Args:
            tokens: Liste des tokens détectés
            source_dir: Code source à analyser

        Returns:
            Rapport d'analyse de stockage
        """
        findings = self.scan_directory(source_dir)

        # Filtrer les findings liés aux tokens
        token_findings = [
            f for f in findings
            if f.get("type") in [
                "INSECURE_SHARED_PREFS",
                "SENSITIVE_LOG_LEAK",
                "CREDENTIAL_IN_URL",
                "INSECURE_FILE_STORAGE"
            ]
        ]

        # Calculer un score de sécurité de stockage
        storage_security_score = self._calculate_storage_score(findings)

        return {
            "token_storage_findings": token_findings,
            "all_storage_findings": findings,
            "storage_security_score": storage_security_score,
            "total_findings": len(findings),
            "critical_count": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
            "high_count": sum(1 for f in findings if f.get("severity") == "HIGH"),
            "medium_count": sum(1 for f in findings if f.get("severity") == "MEDIUM"),
        }

    def _calculate_storage_score(self, findings: List[Dict]) -> int:
        """Calcule un score de sécurité de stockage (0-100, plus haut = meilleur)."""
        if not findings:
            return 100

        score = 100
        for finding in findings:
            severity = finding.get("severity", "LOW")
            if severity == "CRITICAL":
                score -= 30
            elif severity == "HIGH":
                score -= 20
            elif severity == "MEDIUM":
                score -= 10
            else:
                score -= 5

        return max(0, score)

    def check_secure_storage_usage(self, source_dir: str) -> Dict[str, Any]:
        """
        Vérifie l'utilisation de mechanisms de stockage sécurisés.

        Returns:
            Dict avec l'état du stockage sécurisé
        """
        result = {
            "encrypted_shared_prefs": False,
            "android_keystore": False,
            "encrypted_file": False,
            "sql_cipher": False,
            "secure_random": False,
            "recommendations": []
        }

        source_path = Path(source_dir)
        if not source_path.exists():
            return result

        # Patterns pour stockage sécurisé
        secure_patterns = {
            "encrypted_shared_prefs": self.ENCRYPTED_PREFS_PATTERNS,
            "android_keystore": self.KEYSTORE_PATTERNS,
            "secure_random": [r'SecureRandom', r'SecureRandom\.getInstance'],
        }

        for ext in ["**/*.java", "**/*.kt"]:
            for file_path in source_path.glob(ext):
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()

                    for key, patterns in secure_patterns.items():
                        if any(re.search(p, content, re.IGNORECASE) for p in patterns):
                            result[key] = True

                except:
                    pass

        # Générer recommandations
        if not result["encrypted_shared_prefs"]:
            result["recommendations"].append(
                "Utiliser EncryptedSharedPreferences pour stocker les tokens et credentials"
            )
        if not result["android_keystore"]:
            result["recommendations"].append(
                "Utiliser Android Keystore pour générer et stocker les clés cryptographiques"
            )
        if not result["secure_random"]:
            result["recommendations"].append(
                "Utiliser SecureRandom au lieu de Random pour la génération de tokens/session IDs"
            )

        return result
