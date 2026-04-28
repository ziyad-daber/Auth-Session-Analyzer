# 🛡️ Auth and Session Analyzer

> Outil d'audit avancé pour la validation de vulnérabilités d'authentification et de session dans les applications Android.

## 🚀 Guide de Lancement Rapide

Suivez ces étapes pour lancer l'outil correctement sur votre machine.

### 1. Préparation de l'Environnement
Assurez-vous d'utiliser l'environnement virtuel Python dédié pour garantir la présence de toutes les dépendances.

```powershell
# Activer l'environnement virtuel (Windows)
.\venv\Scripts\activate
```

### 2. Installation des Dépendances
Si ce n'est pas déjà fait, installez les bibliothèques nécessaires :
```powershell
pip install -r requirements.txt
```

### 3. Lancement du Serveur Backend
Le backend est propulsé par **FastAPI**. Il gère l'analyse statique (JADX), le proxy dynamique (Mitmproxy) et le moteur de corrélation.

```powershell
# Lancer le backend depuis la racine du projet
python backend/main.py
```
*Le serveur démarrera sur **http://127.0.0.1:8000**.*

### 4. Accès au Dashboard
Une fois le backend lancé, ouvrez votre navigateur et accédez à :
👉 **[http://localhost:8000](http://localhost:8000)**

---

## 🛠️ Configuration des Composants

### 📱 Analyse Statique (JADX)
L'outil utilise **JADX** pour décompiler les APK.
- **Chemin configuré :** `tools/jadx/jadx-cli/bin/jadx.bat`
- **Action :** Glissez-déposez un APK dans le dashboard pour lancer le scan automatique.

### 🌐 Analyse Dynamique (Proxy)
- Un proxy MITM est automatiquement lancé sur le port **8080**.
- **Configuration Android :** Réglez le proxy de votre émulateur/téléphone sur l'IP de votre PC et le port configuré.
- **Certificat :** Visitez `mitm.it` sur l'appareil mobile pour installer le certificat CA.

### 🎯 Serveur Cible (InsecureBankv2)
Si vous testez l'APK `InsecureBankv2`, le backend tentera de lancer automatiquement le serveur `AndroLabServer` pour simuler l'API vulnérable.

---

## 📂 Structure du Projet
- `backend/` : Logique API, Analyseurs, Proxy.
- `frontend/` : Interface utilisateur (HTML/JS/CSS).
- `uploads/` : Stockage temporaire des APKs et rapports.
- `reports/` : Rapports PDF générés.

---
> [!IMPORTANT]
> **Audit Réel :** Pour capturer du trafic HTTPS sur Android 7+, vous devez injecter un script Frida de bypass SSL Pinning (intégré dans le module `dynamic_analyzer`).
