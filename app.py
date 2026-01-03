
from flask import Flask, render_template, request, redirect, url_for, session, abort
from security import security_system
import random

app = Flask(__name__)
app.secret_key = 'super_secret_key_change_this_in_prod'

# Mock Data
SENSITIVE_DATA = [
    {"id": 1, "name": "John Doe", "email": "john.doe@example.com", "role": "Admin", "status": "Active"},
    {"id": 2, "name": "Jane Smith", "email": "jane.smith@corporation.com", "role": "CEO", "status": "Active"},
    {"id": 3, "name": "Robert Tables", "email": "bobby.tables@sql.injection", "role": "Developer", "status": "Suspended"},
    {"id": 4, "name": "Alice Wonderland", "email": "alice@rabbit.hole", "role": "Analyst", "status": "Active"},
    {"id": 5, "name": "Eve Monitor", "email": "eve@network.spy", "role": "Security", "status": "Active"},
    {"id": 6, "name": "Mallory Attacker", "email": "mal@malware.com", "role": "External", "status": "Blacklisted"},
    {"id": 7, "name": "Trent Trust", "email": "trent@trust.org", "role": "Notary", "status": "Active"},
    {"id": 8, "name": "Wally Feed", "email": "wally@content.farm", "role": "Intern", "status": "Active"},
    {"id": 9, "name": "Grace Hopper", "email": "grace@cobol.gov", "role": "Engineer", "status": "Retired"},
    {"id": 10, "name": "Ada Lovelace", "email": "ada@first.dev", "role": "Founder", "status": "Legend"},
    {"id": 11, "name": "Linus Torvalds", "email": "penguin@linux.org", "role": "Maintainer", "status": "Active"},
    {"id": 12, "name": "Guido van Rossum", "email": "guido@python.org", "role": "BDFL", "status": "Retired"},
]

@app.before_request
def security_checks():
    ip = request.remote_addr
    user_agent = request.headers.get('User-Agent')

    # 1. Check if IP is already blocked
    if security_system.is_ip_blocked(ip):
        abort(403, description="Access Denied: Your IP has been flagged.")

    # 2. Check User-Agent
    if not security_system.check_user_agent(user_agent):
        security_system.block_ip(ip, f"Suspicious User-Agent: {user_agent}")
        abort(403, description="Access Denied: Suspicious User-Agent detected.")

    # 3. Rate Limiting
    if not security_system.check_rate_limit(ip):
        abort(429, description="Too Many Requests: Slow down.")
    
    # 4. JS Challenge (Simple "Ghost in the browser" check)
    # Skip for static files or login POST (if we want to be strict, we check everywhere)
    if not request.path.startswith('/static') and request.endpoint != 'honeypot':
        if not request.cookies.get('human_verified'):
            # Allow the challenge page to perform headers check/rendering without loop
            # We handle this by returning the challenge template directly if cookie is missing
            # But we must preserve the original destination
            return render_template('challenge.html', target_url=request.url)


@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Simple hardcoded login for demo
        if username == 'user' and password == 'password':
            session['user'] = username
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid credentials")
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', users=SENSITIVE_DATA)

@app.route('/details/<int:user_id>')
def details(user_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    
    user = next((u for u in SENSITIVE_DATA if u['id'] == user_id), None)
    if not user:
        abort(404)
    return render_template('details.html', user=user)

# --- HONEYPOT ROUTE ---
# This route is hidden in CSS but present in HTML.
# Automated scrapers getting all links will likely visit it.
@app.route('/admin-trap-hidden-link')
def honeypot():
    ip = request.remote_addr
    security_system.check_honeypot(ip)
    return "You have been logged.", 200

if __name__ == '__main__':
    # Run slightly slower to simulate real network for 'human' feel if needed, but standard is fine.
    app.run(debug=True, port=5000)
