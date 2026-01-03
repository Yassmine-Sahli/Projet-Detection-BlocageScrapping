
import time
from collections import defaultdict
from flask import request, abort

class SecurityDefense:
    def __init__(self):
        # Storage for Rate Limiting: {ip: [timestamp1, timestamp2, ...]}
        self.request_history = defaultdict(list)
        # Blocked IPs
        self.blocked_ips = set()
        
        # Configuration
        self.RATE_LIMIT_WINDOW = 60  # seconds
        self.RATE_LIMIT_MAX_REQUESTS = 20 # Max requests per window
        self.BLOCKED_USER_AGENTS = [
            "python-requests", "curl", "wget", "scrapy", "bot", "spider", "crawler"
        ]
    
    def is_ip_blocked(self, ip):
        return ip in self.blocked_ips

    def block_ip(self, ip, reason="Unknown"):
        print(f"[SECURITY] Blocking IP {ip}. Reason: {reason}")
        self.blocked_ips.add(ip)
        
    #Cette fonction vérifie si une IP a dépassé la limite de requêtes autorisées
    def check_rate_limit(self, ip):
        if self.is_ip_blocked(ip):
            return False

        current_time = time.time()
        # Clean old requests
        self.request_history[ip] = [t for t in self.request_history[ip] if current_time - t < self.RATE_LIMIT_WINDOW]
        
        # Add new request
        self.request_history[ip].append(current_time)
        
        if len(self.request_history[ip]) > self.RATE_LIMIT_MAX_REQUESTS:
            self.block_ip(ip, "Rate Limit Exceeded")
            return False
            
        return True
    
    #Cette fonction vérifie si l'agent utilisateur est suspect en fonction de mots-clés bloqués
    def check_user_agent(self, user_agent):
        if not user_agent:
            return False # Block empty UA
        
        ua_lower = user_agent.lower()
        for bot_keyword in self.BLOCKED_USER_AGENTS:
            if bot_keyword in ua_lower:
                return False
        return True
    
    #cette fonction gère le piège à miel 
    def check_honeypot(self, ip):
        # If this method is called, the user visited the honeypot route
        self.block_ip(ip, "Honeypot Triggered")

security_system = SecurityDefense()
