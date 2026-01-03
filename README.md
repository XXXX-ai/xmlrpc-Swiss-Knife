# ExRPC - WordPress XML-RPC Pentest Swiss Knife

**ExRPC** est un outil en ligne de commande modulaire conçu pour aider les chercheurs en sécurité et les testeurs d’intrusion à analyser et tester les sites WordPress qui exposent l’endpoint `xmlrpc.php`.

> **⚠️ Avertissement légal important**  
> Cet outil est fourni **uniquement à des fins éducatives et de tests de sécurité autorisés**.  
> Toute utilisation contre une cible sans autorisation écrite explicite est illégale.  
> Les auteurs et contributeurs déclinent toute responsabilité en cas d’usage abusif.

Version actuelle : **v3.0** (2026)  
Auteur : Toi + améliorations Grok

## Fonctionnalités principales

- **Vérification de disponibilité** : Teste si `xmlrpc.php` est accessible et fonctionnel.
- **Énumération des méthodes** : Liste les méthodes XML-RPC disponibles via `system.listMethods`.
- **Énumération des utilisateurs** : Tentative basique d'énumération des utilisateurs (via `wp.getUsers` – souvent limité sans authentification).
- **Bruteforce accéléré** : Utilise `system.multicall` pour tester plusieurs mots de passe en une seule requête, accélérant le processus.
- **Test de charge / DoS** : Amplification XML-RPC pour stresser le serveur cible.
- **Test pingback** : Vérifie la fonctionnalité `pingback.ping` (vecteur potentiel pour SSRF).
- **Détection d'IP** : Tentative de révélation de l'IP réelle derrière un proxy ou WAF.
- **Support des proxies** : Permet l'utilisation de proxies pour les tests.
- **Interface utilisateur** : Sortie colorée, barres de progression avec `tqdm`, tableaux formatés avec `tabulate`.
- **Journalisation** : Logs détaillés dans `exrpc_log.txt`.

## Installation

### Prérequis système
- Python 3.8 ou supérieur
- Accès à Internet pour les requêtes HTTP

### Installation des dépendances
Installez les bibliothèques Python requises via `pip` :

```bash
pip install requests tqdm tabulate
```

Ou, si vous utilisez un environnement virtuel :

```bash
python3 -m venv env
source env/bin/activate  # Sur Linux/Mac
pip install requests tqdm tabulate
```

### Téléchargement
Clonez ou téléchargez le script `xmlrpcXploit.py` dans votre répertoire de travail.

## Utilisation

### Syntaxe générale
```bash
python xmlrpcXploit.py <URL_CIBLE> --mode <MODE> [OPTIONS]
```

- `<URL_CIBLE>` : L'URL de base du site WordPress (ex: `http://example.com/`).
- `--mode` : Le mode d'opération (obligatoire). Voir les modes ci-dessous.

### Modes disponibles

| Mode              | Description                                                                 |
|-------------------|-----------------------------------------------------------------------------|
| `scan`           | Exécute tous les tests basiques : énumération méthodes, utilisateurs, pingback, IP disclosure. |
| `enum-methods`   | Énumère uniquement les méthodes XML-RPC disponibles.                       |
| `enum-users`     | Tente d'énumérer les utilisateurs (nécessite souvent des droits).           |
| `brute`          | Effectue un bruteforce de mot de passe pour un utilisateur donné.          |
| `dos`            | Lance une attaque de déni de service par amplification XML-RPC.             |
| `pingback`       | Teste la fonctionnalité pingback pour détecter des vulnérabilités SSRF.    |
| `ip-disclosure`  | Tente de révéler l'IP réelle du serveur.                                   |

### Options communes
- `--proxy <URL>` : Utilise un proxy HTTP/HTTPS (ex: `http://127.0.0.1:8080`).
- `--threads <N>` : Nombre de threads pour le mode DoS (défaut: 50).

### Options spécifiques
- Pour `brute` :
  - `--user <USERNAME>` : Nom d'utilisateur à tester (obligatoire).
  - `--wordlist <FICHIER>` : Chemin vers la liste de mots de passe (obligatoire).

## Exemples d'utilisation

### 1. Mode scan complet
```bash
python xmlrpcXploit.py http://example.com/ --mode scan
```
Effectue une analyse complète : vérifie la disponibilité, énumère méthodes et utilisateurs, teste pingback et IP disclosure.

### 2. Énumération des méthodes
```bash
python xmlrpcXploit.py http://example.com/ --mode enum-methods
```
Affiche une liste formatée des méthodes XML-RPC disponibles.

### 3. Énumération des utilisateurs
```bash
python xmlrpcXploit.py http://example.com/ --mode enum-users
```
Tente de lister les utilisateurs du site.

### 4. Bruteforce de mot de passe
```bash
python xmlrpcXploit.py http://example.com/ --mode brute --user admin --wordlist rockyou.txt
```
Teste des mots de passe pour l'utilisateur `admin` en utilisant la wordlist `rockyou.txt`. Utilise `system.multicall` pour accélérer.

### 5. Test DoS
```bash
python xmlrpcXploit.py http://example.com/ --mode dos --threads 100
```
Lance une attaque de DoS avec 100 threads.

### 6. Test pingback
```bash
python xmlrpcXploit.py http://example.com/ --mode pingback
```
Teste la fonctionnalité pingback avec une URL par défaut.

### 7. Détection d'IP
```bash
python xmlrpcXploit.py http://example.com/ --mode ip-disclosure
```
Tente de révéler l'IP réelle du serveur.

### 8. Utilisation avec proxy
```bash
python xmlrpcXploit.py http://example.com/ --mode scan --proxy http://127.0.0.1:8080
```
Effectue le scan via un proxy Burp Suite ou similaire.

## Sortie et journalisation

- **Sortie console** : Messages colorés, barres de progression, tableaux pour une meilleure lisibilité.
- **Logs** : Tous les événements sont enregistrés dans `exrpc_log.txt` avec timestamps, niveaux (INFO/ERROR) et détails.
- **Codes de couleur** :
  - Rouge : Erreurs ou échecs.
  - Vert : Succès.
  - Jaune : Avertissements ou informations.
  - Bleu : Informations générales.

## Limitations et considérations

- **Authentification** : Certains modes (comme `enum-users`) peuvent nécessiter des droits d'administrateur ou échouer sans authentification.
- **Protection** : Les sites avec WAF (comme Cloudflare) ou désactivation de XML-RPC peuvent bloquer les tests.
- **Performance** : Le bruteforce et le DoS peuvent être lents ou détectés par les systèmes de sécurité.
- **Éthique** : Utilisez uniquement sur vos propres systèmes ou avec permission explicite.

## Contribution

Les contributions sont les bienvenues ! Ouvrez une issue ou une pull request sur le dépôt GitHub (si applicable).

## Licence

Ce projet est sous licence MIT. Voir le fichier LICENSE pour plus de détails.

## Changelog

- **v3.0 (2026)** : Améliorations générales, ajout de modes, support proxy, journalisation améliorée.
- **v2.0** : Ajout du bruteforce multicall et DoS.
- **v1.0** : Version initiale avec scan basique.

---

Pour plus d'informations ou des rapports de bugs, contactez l'auteur.
