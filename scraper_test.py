
import requests
import time
from bs4 import BeautifulSoup

BASE_URL = "http://127.0.0.1:5000"

def log(msg, status="INFO"):
    print(f"[{status}] {msg}")


"""Naive Bot (Le Nul)**
    *   *Technique :* Utilise la librairie `requests` sans rien changer.
    *   *Résultat :* **ÉCHEC**. Bloqué par la Défense n°1 (User-Agent).
"""
#cette fonction teste un bot naïf avec User-Agent par défaut
def test_naive_bot():
    log("Testing Naive Bot (Default User-Agent)...")
    try:
        response = requests.get(BASE_URL)
        if response.status_code == 403:
            log("Naive Bot BLOCKED as expected.", "SUCCESS")
        else:
            log(f"Naive Bot NOT blocked. Status: {response.status_code}", "FAIL")
    except Exception as e:
        log(f"Connection Error: {e}", "ERROR")

#cette fonction teste un bot intelligent avec User-Agent usurpé
def test_smart_bot_login():
    log("Testing Smart Bot (Spoofed User-Agent) Login...")
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    })

    # 1. Login
    login_data = {'username': 'user', 'password': 'password'}
    try:
        post_resp = session.post(f"{BASE_URL}/login", data=login_data)
        if post_resp.status_code == 200 and "Sensitive Data Dashboard" in post_resp.text:
            log("Smart Bot Logged in Successfully.", "INFO")
        elif post_resp.status_code == 200: 
            # might have redirected or stayed on login
            log("Smart Bot Login Request OK, checking redirection...", "INFO")
        
        # 2. Access Dashboard
        dashboard_resp = session.get(f"{BASE_URL}/dashboard")
        
        # Check if we got the challenge page
        if "Checking browser security" in dashboard_resp.text:
            log("Smart Bot BLOCKED by JS Challenge (Received Security Page).", "SUCCESS")
            return session # Partial success of defense
            
        if "Confidential Personnel List" in dashboard_resp.text:
            log("Smart Bot Accessed Dashboard.", "FAIL (Defense Bypassed - Site Vulnerable!)")
            
            # --- START REAL SCRAPING ---
            soup = BeautifulSoup(dashboard_resp.text, 'html.parser')
            rows = soup.find_all('tr')
            log(f"Found {len(rows)-1} users in the table!", "INFO")
            for row in rows[1:]: # Skip header
                cols = row.find_all('td')
                if cols:
                    name = cols[1].text.strip()
                    email = cols[2].text.strip()
                    log(f"STOLEN DATA: {name} - {email}", "INFO")
            # --- END SCRAPING ---
        else:
            log("Smart Bot BLOCKED. Dashboard Protected.", "SUCCESS (Anti-Scraping Working)")
            
    except Exception as e:
        log(f"Error: {e}", "ERROR")
        return session
    return session


#cette fonction teste un bot ultime qui contourne le défi JS
def test_js_bypassing_bot():
    log("Testing Ultimate Bot (Spoofed UA + Solves JS Challenge)...")
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    })
    # Manually set the cookie the JS would set
    session.cookies.set('human_verified', 'true')

    # Login
    login_data = {'username': 'user', 'password': 'password'}
    try:
        session.post(f"{BASE_URL}/login", data=login_data)
        resp = session.get(f"{BASE_URL}/dashboard")
        if "Confidential Personnel List" in resp.text:
            log("Ultimate Bot Accessed Dashboard (Bypassed JS Challenge).", "INFO")
            return session
    except:
        pass
    return None



def test_honeypot(session):
    log("Testing Honeypot Trigger...")
    # The smart bot decides to visit ALL links it found.
    # It found the hidden link in base.html
    trap_url = f"{BASE_URL}/admin-trap-hidden-link"
    try:
        resp = session.get(trap_url)
        log(f"Bot visited honeypot. Status: {resp.status_code}", "INFO")
        
        # Now try to access home again
        check_resp = session.get(BASE_URL)
        if check_resp.status_code == 403:
            log("Bot IP was BLOCKED after visiting honeypot.", "SUCCESS")
        else:
            log("Bot IP was NOT blocked after visiting honeypot.", "FAIL")
    except Exception as e:
        log(f"Error: {e}", "ERROR")

def test_rate_limit():
    log("Testing Rate Limit (New Session)...")
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    })
    
    count = 0
    blocked = False
    start_time = time.time()
    
    for i in range(25): # Limit is 20 in 60s
        resp = session.get(BASE_URL)
        if resp.status_code == 429:
            log(f"Rate Limit hit at request {i+1}.", "SUCCESS")
            blocked = True
            break
        elif resp.status_code == 403:
             log(f"Blocked (403) at request {i+1}.", "INFO")
             blocked = True
             break
        time.sleep(0.1) # Fast requests
    
    if not blocked:
        log("Rate Limit FAILED (Not triggered within 25 requests).", "FAIL")

if __name__ == "__main__":
    print("--- STARTING ANTI-SCRAPING TESTS ---")
    time.sleep(1) # Wait for server to be ready if called swiftly
    test_naive_bot()
    print("-" * 20)
    smart_session = test_smart_bot_login()
    print("-" * 20)
    # The normal smart bot fails now, so we need the ultimate bot to test honeypot
    ultimate_session = test_js_bypassing_bot()
    print("-" * 20)
    if ultimate_session:
        test_honeypot(ultimate_session)
    print("-" * 20)
    test_rate_limit()
    print("--- TESTS COMPLETED ---")
