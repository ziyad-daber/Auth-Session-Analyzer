# 🛠️ Guide de Dépannage - Auth & Session Validator

Ce guide explique comment résoudre les problèmes courants rencontrés lors de l'analyse dynamique avec un émulateur Android, notamment les problèmes de réseau et de connexion Frida.

## 1. Problèmes de Connexion Réseau (Emulator Offline)
Si l'émulateur ne parvient pas à contacter le serveur (même avec `10.0.2.2`), utilisez le **Tunnel ADB Reverse**. Cela force l'émulateur à utiliser la connexion USB pour atteindre les services sur votre machine.

### Commandes à exécuter :
```powershell
# Rediriger le trafic de l'émulateur vers votre PC
adb reverse tcp:8888 tcp:8888  # Pour le serveur InsecureBank
adb reverse tcp:8000 tcp:8000  # Pour le backend AuthValidator
adb reverse tcp:8080 tcp:8080  # Pour le Proxy MITM
```

### Configuration dans l'application :
Une fois le tunnel activé, utilisez **127.0.0.1** au lieu de `10.0.2.2` dans les paramètres de l'application Android.

---

## 2. Problèmes Frida (Instrumentation)
Si Frida ne parvient pas à s'attacher ou si le dashboard reste vide.

### Vérifier le serveur Frida sur l'appareil :
```powershell
# S'assurer d'être Root
adb root

# Vérifier si le serveur tourne
adb shell pgrep frida-server

# Si non, le relancer
adb shell "/data/local/tmp/frida-server &"
```

### Relancer l'analyse depuis le backend :
```powershell
# Utiliser curl pour forcer le redémarrage
curl -X POST "http://localhost:8000/api/frida/start?package_name=com.android.insecurebankv2"
```

---

## 3. Lancement du Serveur de Test (InsecureBankv2)
L'application Android a besoin d'un serveur pour valider le login.

### Commande :
```powershell
cd c:\Users\hajar\Desktop\projet-mobile\Android-InsecureBankv2\AndroLabServer
python server_v3.py
```
*Note : Utilisez `server_v3.py` pour Python 3.*

---

## 4. Configuration du Proxy
Pour que le trafic soit intercepté par le dashboard :
1.  **Proxy Android** : Réglez le proxy de l'émulateur sur `127.0.0.1:8080` (après avoir fait le `adb reverse`).
2.  **Certificat** : Si vous testez du HTTPS, installez le certificat `mitm.it` sur l'appareil.

---

## 💡 Astuce Dashboard
Si le panneau de droite ne s'affiche pas quand vous cliquez sur un flux, **rafraîchissez la page (F5)**. J'ai corrigé le code JavaScript pour éviter que ce problème ne se reproduise.

---

**Identifiants par défaut (InsecureBank) :** `admin` / `admin@123`
