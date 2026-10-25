#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════╗
║   Dashboard de Cybersécurité — Backend Flask ║
║   Déploiement Vercel (Serverless)            ║
╚══════════════════════════════════════════════╝
"""

import re
import ssl
import math
import json
import socket
import string
import datetime
import hashlib
import os

import requests
import requests.packages.urllib3
from flask import Flask, render_template, request, jsonify, send_from_directory, Response

requests.packages.urllib3.disable_warnings()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(BASE_DIR)
TEMPLATE_DIR = os.path.join(ROOT_DIR, "templates")
STATIC_DIR = os.path.join(ROOT_DIR, "static")

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)


def _load_asset(filename):
    for candidate in [
        os.path.join(ROOT_DIR, filename),
        os.path.join(BASE_DIR, filename),
        os.path.join(ROOT_DIR, "templates", filename),
        os.path.join(BASE_DIR, "templates", filename),
        os.path.join(os.getcwd(), filename),
        filename
    ]:
        if os.path.isfile(candidate):
            with open(candidate, "r", encoding="utf-8") as f:
                return f.read()
    return None


# ══════════════════════════════════════════════
#  ROUTES STATIQUES & PWA (WEB & MOBILE)
# ══════════════════════════════════════════════
@app.route("/")
def index():
    content = _load_asset("templates/index.html") or _load_asset("index.html")
    if content:
        return Response(content, mimetype="text/html")
    return render_template("index.html")


@app.route("/manifest.json")
def manifest():
    content = _load_asset("manifest.json")
    if content:
        return Response(content, mimetype="application/manifest+json")
    return jsonify({
        "name": "CyberDash — Audit IT & Cybersécurité",
        "short_name": "CyberDash",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#080D1A",
        "theme_color": "#080D1A"
    })


@app.route("/sw.js")
def service_worker():
    content = _load_asset("sw.js")
    if content:
        return Response(content, mimetype="application/javascript")
    return Response("// SW fallback\nself.addEventListener('fetch', () => {});", mimetype="application/javascript")


@app.route("/static/<path:filename>")
def serve_static(filename):
    for folder in [STATIC_DIR, os.path.join(BASE_DIR, "static"), os.path.join(os.getcwd(), "static")]:
        if os.path.isdir(folder) and os.path.isfile(os.path.join(folder, filename)):
            return send_from_directory(folder, filename)
    return "", 404


@app.after_request
def apply_security_headers(response):
    # En-têtes de sécurité HTTP renforcés (Strict CSP Level 3 & HSTS Max)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' data: https://fonts.gstatic.com; "
        "img-src 'self' data: blob: https:; "
        "connect-src 'self' https:; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'self'; "
        "upgrade-insecure-requests;"
    )
    response.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Embedder-Policy"] = "credentialless"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    response.headers["Clear-Site-Data"] = '"cache", "cookies", "storage"'
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"

    # Masquage des informations d'exposition serveur (Fingerprinting / Information Disclosure)
    response.headers.pop("Server", None)
    response.headers.pop("X-Powered-By", None)
    return response


# ══════════════════════════════════════════════
#  OUTIL 1 — Audit des En-têtes HTTP
# ══════════════════════════════════════════════
@app.route("/api/audit", methods=["POST"])
def audit_headers():
    data = request.get_json()
    url  = data.get("url", "").strip()

    if not url.startswith("http"):
        url = "https://" + url

    headers_cibles = {
        "Content-Security-Policy": {
            "desc": "Contrôle les ressources autorisées à être chargées (scripts, styles, etc.) pour bloquer XSS et injections.",
            "importance": "Critique",
            "recommandation": "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self'; form-action 'self'; upgrade-insecure-requests;",
            "categorie": "Injections & XSS",
        },
        "Strict-Transport-Security": {
            "desc": "Force l'usage de HTTPS et empêche le déclassement vers HTTP (attaques SSL-stripping).",
            "importance": "Critique",
            "recommandation": "max-age=63072000; includeSubDomains; preload",
            "categorie": "Chiffrement & Transport",
        },
        "X-Frame-Options": {
            "desc": "Protège contre le détournement de clic (clickjacking) en interdisant l'intégration dans des iframes tierces.",
            "importance": "Élevée",
            "recommandation": "DENY ou SAMEORIGIN",
            "categorie": "Intégrité de l'interface",
        },
        "X-Content-Type-Options": {
            "desc": "Empêche le reniflage de type MIME (MIME-sniffing) et force le respect strict du Content-Type déclaré.",
            "importance": "Élevée",
            "recommandation": "nosniff",
            "categorie": "Gestion des types MIME",
        },
        "Referrer-Policy": {
            "desc": "Contrôle la transmission de l'URL référente pour protéger la vie privée des utilisateurs.",
            "importance": "Moyenne",
            "recommandation": "strict-origin-when-cross-origin",
            "categorie": "Confidentialité & Vie privée",
        },
        "Permissions-Policy": {
            "desc": "Restreint l'accès aux APIs sensibles du navigateur (caméra, micro, géolocalisation, capteurs).",
            "importance": "Moyenne",
            "recommandation": "camera=(), microphone=(), geolocation=()",
            "categorie": "Permissions & APIs",
        },
        "Cross-Origin-Opener-Policy": {
            "desc": "Isole le contexte de navigation de la page contre les attaques inter-fenêtres et Spectre.",
            "importance": "Moyenne",
            "recommandation": "same-origin",
            "categorie": "Isolation Cross-Origin",
        },
        "Cross-Origin-Embedder-Policy": {
            "desc": "Empêche le document de charger des ressources tierces sans autorisation explicite CORS ou CORP.",
            "importance": "Moyenne",
            "recommandation": "require-corp ou credentialless",
            "categorie": "Isolation Cross-Origin",
        },
        "Cross-Origin-Resource-Policy": {
            "desc": "Protège les ressources sensibles contre l'inclusion illégitime par d'autres origines.",
            "importance": "Moyenne",
            "recommandation": "same-origin ou same-site",
            "categorie": "Isolation Cross-Origin",
        },
        "X-Permitted-Cross-Domain-Policies": {
            "desc": "Restreint le chargement de politiques cross-domain pour les clients tiers (Flash, PDF).",
            "importance": "Faible",
            "recommandation": "none",
            "categorie": "Clients tiers",
        },
        "Cache-Control": {
            "desc": "Empêche la mise en cache de données sensibles sur les proxys publics et navigateurs.",
            "importance": "Recommandé",
            "recommandation": "no-store, max-age=0 (sur les endpoints sensibles)",
            "categorie": "Gestion du Cache",
        },
        "Clear-Site-Data": {
            "desc": "Permet d'ordonner la purge des données de session (cookies, storage, cache) lors de la déconnexion.",
            "importance": "Optionnel",
            "recommandation": "\"cache\", \"cookies\", \"storage\"",
            "categorie": "Session & Déconnexion",
        },
        "X-XSS-Protection": {
            "desc": "Protection XSS historique (dépréciée au profit de CSP, souvent configurée à 0).",
            "importance": "Historique",
            "recommandation": "0 (recommandé si CSP actif) ou 1; mode=block",
            "categorie": "Injections & XSS",
        },
    }

    headers_exposition = {
        "Server":              "Divulgue le logiciel et éventuellement la version du serveur web.",
        "X-Powered-By":        "Divulgue le langage ou framework backend (ex: PHP, Express, ASP.NET).",
        "X-AspNet-Version":    "Divulgue la version du framework ASP.NET.",
        "X-AspNetMvc-Version": "Divulgue la version d'ASP.NET MVC.",
        "X-Generator":         "Divulgue le CMS ou générateur (ex: WordPress, Drupal).",
        "X-Runtime":           "Divulgue le temps d'exécution serveur (Ruby/Rails).",
    }

    critiques_cles = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
    ]

    resultats = []
    score     = 0

    try:
        reponse = requests.get(url, timeout=10, verify=False)
        recu    = reponse.headers

        for h, meta in headers_cibles.items():
            present = h in recu
            valeur  = recu.get(h, "—")
            if present:
                score += 1

            # Diagnostic de durcissement renforcé
            diagnostic = None
            if present and h == "Content-Security-Policy":
                checks = []
                if "default-src 'self'" in valeur:
                    checks.append("default-src strict")
                if "object-src 'none'" in valeur:
                    checks.append("object-src 'none'")
                if "'unsafe-eval'" not in valeur:
                    checks.append("sans unsafe-eval")
                if "frame-ancestors" in valeur:
                    checks.append("anti-clickjacking")
                if "upgrade-insecure-requests" in valeur:
                    checks.append("upgrade HTTPS")
                diagnostic = "Durcissement renforcé : " + ", ".join(checks) if checks else "CSP standard"
            elif present and h == "Strict-Transport-Security":
                checks = []
                if "includeSubDomains" in valeur:
                    checks.append("sous-domaines inclus")
                if "preload" in valeur:
                    checks.append("preload éligible")
                if "63072000" in valeur:
                    checks.append("durée 2 ans (HSTS Max)")
                elif "31536000" in valeur:
                    checks.append("durée 1 an")
                diagnostic = "Durcissement renforcé : " + ", ".join(checks) if checks else "HSTS standard"

            resultats.append({
                "header":         h,
                "present":        present,
                "valeur":         valeur,
                "desc":           meta["desc"],
                "importance":     meta["importance"],
                "recommandation": meta["recommandation"],
                "categorie":      meta["categorie"],
                "diagnostic":     diagnostic,
            })

        critiques_ok = sum(1 for c in critiques_cles if c in recu)

        # Calcul de la note globale (Grade de sécurité)
        if critiques_ok == 4:
            grade = ("A+", "Excellente protection", "vert") if score >= 10 else ("A", "Très bonne protection", "vert")
        elif critiques_ok == 3:
            grade = ("B", "Bonne protection", "vert")
        elif critiques_ok == 2:
            grade = ("C", "Protection moyenne", "jaune")
        elif critiques_ok == 1:
            grade = ("D", "Protection faible", "orange")
        else:
            grade = ("F", "Non sécurisé (headers critiques manquants)", "rouge")

        # Analyse des fuites d'informations (Information Disclosure)
        fuites = []
        for h_expo, desc_expo in headers_exposition.items():
            if h_expo in recu:
                val = recu.get(h_expo, "").strip()
                a_version = bool(re.search(r"\d+\.\d+", val))
                fuites.append({
                    "header":          h_expo,
                    "valeur":          val,
                    "desc":            desc_expo,
                    "version_exposee": a_version,
                    "conseil":         "Masquer ou supprimer cet en-tête en production pour limiter l'empreinte technique (fingerprinting).",
                })

        return jsonify({
            "ok":          True,
            "url":         url,
            "status_code": reponse.status_code,
            "score":       score,
            "total":       len(headers_cibles),
            "grade": {
                "lettre":  grade[0],
                "label":   grade[1],
                "couleur": grade[2],
            },
            "critiques": {
                "ok":    critiques_ok,
                "total": len(critiques_cles),
            },
            "serveur":     recu.get("Server", "Non divulgué"),
            "fuites":      fuites,
            "resultats":   resultats,
        })

    except Exception as e:
        return jsonify({"ok": False, "erreur": str(e)})


# ══════════════════════════════════════════════
#  OUTIL 2 — Vérification SSL
# ══════════════════════════════════════════════
@app.route("/api/ssl", methods=["POST"])
def verif_ssl():
    data   = request.get_json()
    url    = data.get("url", "").strip()
    domaine = url.replace("https://", "").replace("http://", "").split("/")[0]

    if not url.startswith("https"):
        return jsonify({
            "ok":      False,
            "https":   False,
            "message": "Le site n'utilise pas HTTPS — données en clair sur le réseau !",
        })

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domaine, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domaine) as ssock:
                cert    = ssock.getpeercert()
                version = ssock.version()

        expire_str  = cert.get("notAfter", "")
        expire_date = datetime.datetime.strptime(expire_str, "%b %d %H:%M:%S %Y %Z")
        jours       = (expire_date - datetime.datetime.utcnow()).days

        issuer = dict(x[0] for x in cert.get("issuer", []))
        sujet  = dict(x[0] for x in cert.get("subject", []))

        return jsonify({
            "ok":         True,
            "https":      True,
            "version_tls":version,
            "expire":     expire_date.strftime("%d/%m/%Y"),
            "jours":      jours,
            "issuer":     issuer.get("organizationName", "Inconnu"),
            "domaine":    sujet.get("commonName", domaine),
        })

    except ssl.CertificateError as e:
        return jsonify({"ok": False, "https": True, "erreur": f"Certificat invalide : {e}"})
    except Exception as e:
        return jsonify({"ok": False, "erreur": str(e)})


# ══════════════════════════════════════════════
#  OUTIL 3 — Scan de Ports (cible configurable)
# ══════════════════════════════════════════════
import ipaddress

PORTS_INFO = {
    21:    {"service": "FTP",        "risque": "moyen",  "note": "Transfert de fichiers non chiffré"},
    22:    {"service": "SSH",        "risque": "faible", "note": "Accès distant sécurisé"},
    23:    {"service": "Telnet",     "risque": "élevé",  "note": "Accès distant NON chiffré — dangereux !"},
    25:    {"service": "SMTP",       "risque": "moyen",  "note": "Envoi d'emails"},
    53:    {"service": "DNS",        "risque": "faible", "note": "Résolution de noms de domaine"},
    80:    {"service": "HTTP",       "risque": "faible", "note": "Web non sécurisé"},
    110:   {"service": "POP3",       "risque": "moyen",  "note": "Réception d'emails (non chiffré)"},
    143:   {"service": "IMAP",       "risque": "moyen",  "note": "Réception d'emails"},
    443:   {"service": "HTTPS",      "risque": "faible", "note": "Web sécurisé"},
    3306:  {"service": "MySQL",      "risque": "élevé",  "note": "Base de données exposée sur réseau"},
    5432:  {"service": "PostgreSQL", "risque": "élevé",  "note": "Base de données exposée sur réseau"},
    6379:  {"service": "Redis",      "risque": "élevé",  "note": "Cache sans auth par défaut"},
    8080:  {"service": "HTTP-Alt",   "risque": "faible", "note": "Souvent utilisé en développement"},
    27017: {"service": "MongoDB",    "risque": "élevé",  "note": "Base de données sans auth par défaut"},
}


def _est_ip_privee(host: str) -> bool:
    """Retourne True si l'hôte résout vers une adresse IP privée/réservée."""
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
    except ValueError:
        try:
            resolved = socket.gethostbyname(host)
            ip = ipaddress.ip_address(resolved)
            return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
        except Exception:
            return False


# Plages d'IP Cloudflare (source : https://www.cloudflare.com/ips/)
CLOUDFLARE_RANGES = [
    ipaddress.ip_network("103.21.244.0/22"),
    ipaddress.ip_network("103.22.200.0/22"),
    ipaddress.ip_network("103.31.4.0/22"),
    ipaddress.ip_network("104.16.0.0/13"),
    ipaddress.ip_network("104.24.0.0/14"),
    ipaddress.ip_network("108.162.192.0/18"),
    ipaddress.ip_network("131.0.72.0/22"),
    ipaddress.ip_network("141.101.64.0/18"),
    ipaddress.ip_network("162.158.0.0/15"),
    ipaddress.ip_network("172.64.0.0/13"),
    ipaddress.ip_network("173.245.48.0/20"),
    ipaddress.ip_network("188.114.96.0/20"),
    ipaddress.ip_network("190.93.240.0/20"),
    ipaddress.ip_network("197.234.240.0/22"),
    ipaddress.ip_network("198.41.128.0/17"),
]

def _detecter_cdn(ip_str: str) -> str | None:
    """Retourne le nom du CDN si l'IP lui appartient, sinon None."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for reseau in CLOUDFLARE_RANGES:
            if ip in reseau:
                return "Cloudflare"
    except Exception:
        pass
    return None


@app.route("/api/ports", methods=["POST"])
def scan_ports():
    data   = request.get_json() or {}
    target = data.get("target", "").strip()

    if not target:
        return jsonify({"ok": False, "erreur": "Aucune cible spécifiée."})

    # Nettoyer : enlever http(s):// si l'utilisateur a collé une URL
    target = target.replace("https://", "").replace("http://", "").split("/")[0].split(":")[0]

    # Résoudre l'IP réelle du domaine
    ip_resolue = None
    try:
        ip_resolue = socket.gethostbyname(target)
    except Exception:
        return jsonify({"ok": False, "erreur": f"Impossible de résoudre '{target}'. Vérifie le nom de domaine."})

    # Bloquer les IPs privées
    if _est_ip_privee(ip_resolue):
        return jsonify({
            "ok":    True,
            "cible": target,
            "ip":    ip_resolue,
            "ports": [],
            "total": 0,
            "avertissement": (
                f"'{target}' pointe vers {ip_resolue} (adresse privée/locale). "
                "En environnement cloud (Vercel), ce n'est pas ta machine. "
                "Lance l'app en local ou entre un domaine/IP public."
            ),
        })

    # Détecter si le domaine est derrière un CDN (Cloudflare, etc.)
    cdn = _detecter_cdn(ip_resolue)
    info_hebergement = None
    if cdn == "Cloudflare":
        info_hebergement = (
            f"⚡ Ce domaine est derrière {cdn} (IP : {ip_resolue}). "
            "Cloudflare agit comme proxy : l'IP scannée est celle de Cloudflare, "
            "pas celle de ton serveur réel. Les ports ouverts (80, 443) sont ceux de Cloudflare. "
            "Pour voir les ports de ton vrai serveur, désactive le proxy Cloudflare "
            "(nuage orange → gris dans le DNS Cloudflare) le temps du scan."
        )

    # Check HTTP/HTTPS spécifique au domaine (domain-aware même sur mutualisé)
    http_check = {}
    for scheme in ("https", "http"):
        try:
            r = requests.get(
                f"{scheme}://{target}",
                timeout=4, verify=False,
                allow_redirects=True,
                headers={"Host": target}
            )
            http_check[scheme] = {
                "ok":          True,
                "status_code": r.status_code,
                "server":      r.headers.get("Server", "Non divulgué"),
                "final_url":   r.url,
            }
        except Exception as e:
            http_check[scheme] = {"ok": False, "erreur": str(e)[:80]}

    # Scan TCP sur la liste de ports connus (sur l'IP résolue)
    ouverts = []
    for port, info in PORTS_INFO.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)  # 14 ports × 0.5s = 7s max < limite Vercel 10s
            if sock.connect_ex((ip_resolue, port)) == 0:
                ouverts.append({"port": port, **info})
            sock.close()
        except Exception:
            pass

    return jsonify({
        "ok":               True,
        "cible":            target,
        "ip":               ip_resolue,
        "cdn":              cdn,
        "info_hebergement": info_hebergement,
        "http_check":       http_check,
        "ports":            ouverts,
        "total":            len(ouverts),
    })


# ══════════════════════════════════════════════
#  OUTIL 4 — Analyseur de Mot de Passe
# ══════════════════════════════════════════════
@app.route("/api/password", methods=["POST"])
def analyser_mdp():
    data = request.get_json()
    mdp  = data.get("password", "")

    if not mdp:
        return jsonify({"ok": False, "erreur": "Mot de passe vide"})

    checks = {
        "longueur_ok":    len(mdp) >= 12,
        "majuscules":     any(c.isupper() for c in mdp),
        "minuscules":     any(c.islower() for c in mdp),
        "chiffres":       any(c.isdigit() for c in mdp),
        "speciaux":       any(c in string.punctuation for c in mdp),
        "pas_commun":     mdp.lower() not in MOTS_COMMUNS,
        "pas_repetition": not re.search(r"(.)\1{2,}", mdp),
        "pas_sequence":   not any(seq in mdp.lower() for seq in ["123", "abc", "qwerty", "azerty"]),
    }

    # Calcul de l'entropie (mesure de l'imprévisibilité)
    charset = 0
    if any(c.islower() for c in mdp):   charset += 26
    if any(c.isupper() for c in mdp):   charset += 26
    if any(c.isdigit() for c in mdp):   charset += 10
    if any(c in string.punctuation for c in mdp): charset += 32

    entropie = round(len(mdp) * math.log2(charset), 1) if charset else 0

    score = sum(checks.values())

    if score <= 3:      niveau = "Très faible"
    elif score <= 5:    niveau = "Faible"
    elif score <= 6:    niveau = "Moyen"
    elif score == 7:    niveau = "Fort"
    else:               niveau = "Très fort"

    # Hash SHA-256 (pour montrer le concept — jamais stocker mdp en clair)
    hash_sha256 = hashlib.sha256(mdp.encode()).hexdigest()

    return jsonify({
        "ok":         True,
        "score":      score,
        "total":      len(checks),
        "niveau":     niveau,
        "entropie":   entropie,
        "longueur":   len(mdp),
        "checks":     checks,
        "hash_demo":  hash_sha256[:16] + "...",  # aperçu seulement
    })


# ══════════════════════════════════════════════
#  OUTIL 5 — Détecteur de Phishing
# ══════════════════════════════════════════════
@app.route("/api/phishing", methods=["POST"])
def detecter_phishing():
    data = request.get_json()
    url  = data.get("url", "").strip()

    if not url.startswith("http"):
        url = "http://" + url

    alertes   = []
    score     = 0  # Plus le score est haut, plus l'URL est suspecte

    # Règle 1 — Longueur excessive
    if len(url) > 75:
        alertes.append({"msg": f"URL très longue ({len(url)} caractères)", "poids": 2})
        score += 2

    # Règle 2 — Présence d'une IP au lieu d'un domaine
    if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
        alertes.append({"msg": "Adresse IP au lieu d'un nom de domaine", "poids": 3})
        score += 3

    # Règle 3 — Mots suspects dans l'URL
    mots_suspects = ["login", "secure", "account", "update", "verify",
                     "banking", "paypal", "amazon", "google", "microsoft",
                     "confirm", "password", "signin", "wallet", "urgent"]
    for mot in mots_suspects:
        if mot in url.lower():
            alertes.append({"msg": f"Mot suspect détecté : '{mot}'", "poids": 2})
            score += 2
            break

    # Règle 4 — Trop de sous-domaines
    try:
        domaine = url.split("//")[1].split("/")[0]
        parties = domaine.split(".")
        if len(parties) > 4:
            alertes.append({"msg": f"Trop de sous-domaines ({len(parties)-2})", "poids": 2})
            score += 2
    except Exception:
        pass

    # Règle 5 — Caractères spéciaux suspects
    if "@" in url:
        alertes.append({"msg": "Symbole '@' dans l'URL (redirection cachée)", "poids": 3})
        score += 3

    if url.count("-") > 4:
        alertes.append({"msg": f"Trop de tirets dans le domaine ({url.count('-')})", "poids": 1})
        score += 1

    # Règle 6 — Pas de HTTPS
    if not url.startswith("https"):
        alertes.append({"msg": "Site sans HTTPS — données non chiffrées", "poids": 2})
        score += 2

    # Règle 7 — Extension de domaine inhabituelle
    extensions_suspectes = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click"]
    for ext in extensions_suspectes:
        if url.lower().endswith(ext) or f"{ext}/" in url.lower():
            alertes.append({"msg": f"Extension de domaine suspecte : {ext}", "poids": 2})
            score += 2
            break

    # Verdict
    if score == 0:      verdict, couleur = "Aucune anomalie détectée", "vert"
    elif score <= 3:    verdict, couleur = "Légèrement suspect", "jaune"
    elif score <= 6:    verdict, couleur = "Probablement du phishing", "orange"
    else:               verdict, couleur = "Très probablement du phishing !", "rouge"

    return jsonify({
        "ok":      True,
        "url":     url,
        "score":   min(score, 10),
        "verdict": verdict,
        "couleur": couleur,
        "alertes": alertes,
    })


# ══════════════════════════════════════════════
#  Liste de mots de passe communs (éducatif)
# ══════════════════════════════════════════════
MOTS_COMMUNS = {
    "password", "123456", "password123", "admin", "letmein",
    "welcome", "monkey", "1234567890", "qwerty", "azerty",
    "iloveyou", "sunshine", "princess", "football", "superman",
    "motdepasse", "bonjour", "soleil", "abcdef", "111111"
}


# ══════════════════════════════════════════════
#  OUTIL 6 — Analyseur SQL Injection & Auth (SaaS/B2B)
# ══════════════════════════════════════════════
@app.route("/api/audit/sqli", methods=["POST"])
def audit_sqli():
    data = request.get_json() or {}
    source = (data.get("source") or data.get("payload") or data.get("code_query") or data.get("input") or "").strip()

    if not source:
        return jsonify({"ok": False, "erreur": "Veuillez fournir une requête, un paramètre ou un extrait de code à auditer."})

    patterns = [
        (r"(?i)(\bOR\b|\bAND\b)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?", "Tautologie / Bypass booléen ('1'='1')", "Critique", "Permet de forcer une condition vraie pour contourner une authentification ou extraire toutes les données."),
        (r"(?i)(\bOR\b|\bAND\b)\s+['\"][a-z0-9]+['\"]\s*=\s*['\"][a-z0-9]+['\"]", "Tautologie de chaîne ('a'='a')", "Critique", "Contourne la clause WHERE dans les requêtes de recherche ou d'authentification."),
        (r"(?i)\bUNION\s+(ALL\s+)?SELECT\b", "Injection UNION-based", "Critique", "Permet d'extraire des données sensibles d'autres tables de la base de données."),
        (r"(?i)(--|#|/\*.*?\*/)", "Commentaire SQL injecté", "Élevée", "Permet de tronquer la fin d'une requête légitime pour neutraliser les contrôles (ex: vérification de mot de passe)."),
        (r"(?i)\b(WAITFOR\s+DELAY|PG_SLEEP|SLEEP\s*\(|BENCHMARK\s*\()", "Injection aveugle Time-based", "Élevée", "Permet d'exfiltrer des données caractère par caractère en mesurant le temps de réponse du serveur."),
        (r"(?i)\b(EXEC\s+xp_cmdshell|SYSTEM_USER|CONVERT\s*\(|CAST\s*\(.*?\bAS\b|\b@@version|\bVERSION\s*\(\))", "Exécution système / Énumération version BDD", "Critique", "Permet la divulgation d'informations techniques ou l'exécution de commandes système sur le serveur."),
        (r"(?i);\s*(DROP|DELETE|UPDATE|INSERT|TRUNCATE)\b", "Requêtes empilées (Stacked Queries)", "Critique", "Permet la modification ou destruction directe de données dans la base."),
        (r"(?i)\b(SELECT\s+.*?\bFROM\s+(INFORMATION_SCHEMA|PG_CATALOG|SYSOBJECTS))", "Cartographie de schéma (Reconnaissance BDD)", "Élevée", "Permet à l'attaquant de découvrir la structure des tables et colonnes."),
        (r"(?i)\b(password|passwd|pwd|token|jwt|api_key)\b.*?[=:]\s*['\"][^'\"]+['\"]", "Secret / Identifiant en clair", "Moyenne", "Identifiant ou secret d'API codé en dur sans protection cryptographique."),
    ]

    concat_patterns = [
        (r"""(?i)["'].*?SELECT.*?(WHERE|FROM).*?["']\s*\+\s*[a-zA-Z0-9_]+""", "Concaténation directe de chaîne (+)", "Critique", "Construction dynamique de requête SQL sans requêtes préparées."),
        (r"""(?i)f["'].*?SELECT.*?(WHERE|FROM).*?\{[a-zA-Z0-9_]+\}""", "F-string Python dans requête SQL", "Critique", "Interpolation directe d'une variable non assainie dans une chaîne SQL."),
        (r"""(?i)["'].*?SELECT.*?(WHERE|FROM).*?["']\s*%\s*[a-zA-Z0-9_]+""", "Formatage SQL avec opérateur %", "Critique", "Formatage direct d'une chaîne SQL sans paramètres liés.")
    ]

    findings = []
    score_risque = 0

    for regex, titre, gravite, desc in patterns:
        matches = list(re.finditer(regex, source))
        if matches:
            points = 25 if gravite == "Critique" else (15 if gravite == "Élevée" else 10)
            score_risque += points * len(matches)
            for m in matches:
                findings.append({
                    "titre": titre,
                    "gravite": gravite,
                    "match": m.group(0),
                    "description": desc,
                })

    for regex, titre, gravite, desc in concat_patterns:
        m = re.search(regex, source)
        if m:
            score_risque += 30
            findings.append({
                "titre": titre,
                "gravite": gravite,
                "match": m.group(0),
                "description": desc,
            })

    score_risque = min(score_risque, 100)
    vulnerable = len(findings) > 0

    if score_risque >= 70:
        niveau = "CRITIQUE"
        couleur = "rouge"
        verdict = "Vulnérabilité critique d'injection SQL — Risque d'extraction massive ou de contournement d'authentification."
    elif score_risque >= 40:
        niveau = "ÉLEVÉ"
        couleur = "orange"
        verdict = "Risque élevé — Motifs d'injection ou pratiques de concaténation non sécurisées détectés."
    elif score_risque > 0:
        niveau = "MODÉRÉ"
        couleur = "jaune"
        verdict = "Anomalies ou motifs suspects détectés nécessitant une vérification du code."
    else:
        niveau = "SAIN / SÉCURISÉ"
        couleur = "vert"
        verdict = "Aucun vecteur d'injection SQL classique identifié dans cet extrait."

    return jsonify({
        "ok": True,
        "vulnerable": vulnerable,
        "score_risque": score_risque,
        "niveau": niveau,
        "couleur": couleur,
        "verdict": verdict,
        "nb_constats": len(findings),
        "constats": findings,
        "findings": findings,
        "recommandations": [
            "Utiliser systématiquement des requêtes préparées avec paramètres liés (Prepared Statements / Parameterized Queries).",
            "Appliquer le principe du moindre privilège au compte de base de données utilisé par l'application (pas de droits DROP/ALTER).",
            "Mettre en place une validation stricte des entrées sur liste blanche (allowlist).",
            "Pour l'authentification SaaS, implémenter un hachage robuste (Argon2id ou bcrypt avec sel) et du MFA obligatoire."
        ],
        "norme_ref": "ISO/IEC 27001:2022 A.8.26 & A.8.28 / OWASP Top 10 A03:2021-Injection"
    })


# ══════════════════════════════════════════════
#  OUTIL 7 — Audit de Code Source & Scripts (C, JS/React, Python, Bash)
# ══════════════════════════════════════════════
@app.route("/api/audit/code", methods=["POST"])
def audit_code():
    data = request.get_json() or {}
    code = data.get("code", "")
    langage = (data.get("langage") or data.get("language") or "c").lower()

    if not code.strip():
        return jsonify({"ok": False, "erreur": "Veuillez soumettre un extrait de code à auditer."})

    lines = code.split("\n")
    findings = []

    rules = {
        "c": [
            (r"\bstrcpy\s*\(", "Utilisation de strcpy()", "Critique", "strcpy() ne vérifie pas la taille du buffer de destination. Risque majeur de débordement de tampon (Buffer Overflow). Remplacer par strncpy() ou snprintf()."),
            (r"\bgets\s*\(", "Utilisation de gets()", "Critique", "gets() est formellement bannie du standard C car impossible à sécuriser. Remplacer par fgets()."),
            (r"\bsprintf\s*\(", "Utilisation de sprintf()", "Élevée", "Risque de débordement si la chaîne formatée dépasse la mémoire allouée. Utiliser snprintf()."),
            (r"\bsystem\s*\(", "Appel système direct system()", "Critique", "system() invoque un shell (/bin/sh) et est vulnérable à l'injection de commandes si l'argument contient une entrée utilisateur."),
            (r"\bstrcat\s*\(", "Utilisation de strcat()", "Élevée", "Risque de dépassement de tampon lors de la concaténation. Utiliser strncat()."),
        ],
        "javascript": [
            (r"dangerouslySetInnerHTML", "dangerouslySetInnerHTML (React)", "Critique", "Injection brute de HTML dans le DOM. Risque direct de faille XSS (Cross-Site Scripting)."),
            (r"\beval\s*\(", "Utilisation de eval()", "Critique", "eval() exécute du code arbitraire avec les privilèges du script. À proscrire formellement."),
            (r"document\.write\s*\(", "document.write() non sécurisé", "Élevée", "Pratique obsolète permettant l'injection de scripts malveillants."),
            (r"localStorage\.setItem\s*\(\s*['\"][^'\"]*(token|jwt|auth|password)", "Stockage de jeton sensible dans localStorage", "Élevée", "localStorage est accessible par n'importe quel script JavaScript de la page (vulnérable au vol par XSS). Préférer un cookie httpOnly, Secure, SameSite."),
            (r"(api[_-]?key|secret|password|bearer)\s*[:=]\s*['\"][A-Za-z0-9_-]{8,}['\"]", "Clé API ou secret en clair dans le code JS/React", "Critique", "Le code frontend est entièrement public. Ne jamais intégrer de secrets ou clés privées dans un composant React."),
        ],
        "python": [
            (r"subprocess\.(Popen|run|call)\s*\(.*?\bshell\s*=\s*True", "Option shell=True dans subprocess", "Critique", "shell=True exécute la commande via le shell système et expose directement à l'injection de commandes OS. Passer les arguments sous forme de liste."),
            (r"os\.system\s*\(", "Utilisation de os.system()", "Critique", "os.system() passe directement la commande au shell. Remplacer par subprocess.run(['commande', 'arg'], shell=False)."),
            (r"\beval\s*\(|\bexec\s*\(", "Exécution dynamique eval() / exec()", "Critique", "Permet l'exécution de code Python arbitraire. Risque de compromission totale (RCE)."),
            (r"pickle\.loads?\s*\(", "Désérialisation non sécurisée avec pickle", "Critique", "pickle n'est pas conçu pour être sécurisé contre les données malveillantes. Un attaquant peut forger un payload exécutable. Préférer JSON."),
            (r"""(password|secret_key|api_key|token)\s*=\s*['\"][^'\"]{4,}['\"]""", "Mot de passe ou clé codé en dur", "Élevée", "Les identifiants doivent être extraits dans des variables d'environnement ou un coffre-fort de secrets (Vault/Secret Manager)."),
        ],
        "bash": [
            (r"curl\s+.*?\|\s*(sudo\s+)?bash", "Pipe distant direct vers bash (curl | bash)", "Critique", "Exécution directe d'un script distant non vérifié sans contrôle d'intégrité (hash SHA-256) ni validation préalable."),
            (r"eval\s+.*?\$", "Utilisation de eval avec variables", "Critique", "Évaluation dynamique de commandes bash avec risque d'injection de commandes."),
            (r"rm\s+-rf\s+\$[a-zA-Z0-9_]+", "rm -rf sur variable non quotée", "Élevée", "Si la variable est vide ou non définie, cela peut exécuter rm -rf / et détruire le système."),
            (r"chmod\s+777\b", "Permissions excessives chmod 777", "Élevée", "Accorde les droits complets (rwx) à tous les utilisateurs. Violation du principe du moindre privilège."),
        ]
    }

    active_rules = rules.get(langage, rules["c"])

    for i, line in enumerate(lines, start=1):
        for pattern, titre, severite, desc in active_rules:
            if re.search(pattern, line, re.IGNORECASE):
                findings.append({
                    "ligne": i,
                    "code_snippet": line.strip()[:100],
                    "titre": titre,
                    "severite": severite,
                    "explication": desc,
                })

    score = max(0, 100 - sum(30 if f["severite"] == "Critique" else (15 if f["severite"] == "Élevée" else 5) for f in findings))

    return jsonify({
        "ok": True,
        "langage": langage,
        "total_lignes": len(lines),
        "nb_anomalies": len(findings),
        "score_qualite_securite": score,
        "score_securite": score,
        "constats": findings,
        "findings": findings,
        "norme_ref": "ISO/IEC 27001:2022 A.8.28 Analyse de code source & OWASP Secure Coding Practices"
    })


# ══════════════════════════════════════════════
#  OUTIL 8 — Interpréteur Réseau & Cartographie (Nmap / Burp Suite)
# ══════════════════════════════════════════════
@app.route("/api/audit/nmap-burp", methods=["POST"])
def audit_nmap_burp():
    data = request.get_json() or {}
    raw_text = (data.get("raw_text") or data.get("content") or data.get("text") or "").strip()
    mode = data.get("mode", "nmap")

    if not raw_text:
        return jsonify({"ok": False, "erreur": "Veuillez coller un extrait de sortie Nmap ou une requête/réponse Burp Suite."})

    if mode == "nmap":
        os_detecte = "Non déterminé"
        if re.search(r"(?i)kali", raw_text):
            os_detecte = "Linux Kali (Distribution orientée Pentest / Sécurité offensive)"
        elif re.search(r"(?i)ubuntu|debian", raw_text):
            os_detecte = "Linux (Debian / Ubuntu Server)"
        elif re.search(r"(?i)windows\s+(server\s+\d+|10|11)", raw_text):
            m = re.search(r"(?i)windows\s+(server\s+\d+|10|11)", raw_text)
            os_detecte = f"Microsoft Windows ({m.group(0)})"
        elif re.search(r"(?i)linux", raw_text):
            os_detecte = "Système d'exploitation Linux (Générique)"
        elif re.search(r"(?i)cisco|fortinet|juniper|pfsense", raw_text):
            os_detecte = "Équipement d'infrastructure réseau / Pare-feu"

        port_lines = re.findall(r"(\d+)/(tcp|udp)\s+(\w+)\s+([^\s]+)(?:\s+(.*))?", raw_text)
        ports_analyses = []
        services_dangereux = []

        risques_ports = {
            21: ("FTP", "Critique", "Transfert de fichiers non chiffré - mots de passe et données en clair."),
            22: ("SSH", "Faible", "Accès distant sécurisé (désactiver root et forcer clés Ed25519/RSA)."),
            23: ("Telnet", "Critique", "Administration en texte clair extrêmement vulnérable aux interceptions."),
            25: ("SMTP", "Moyenne", "Vérifier la configuration anti-relais ouvert (Open Relay) et TLS obligatoire."),
            53: ("DNS", "Faible", "Vérifier que les transferts de zone (AXFR) sont interdits aux clients non autorisés."),
            80: ("HTTP", "Moyenne", "Trafic web non chiffré. Redirection automatique vers HTTPS (443) requise."),
            135: ("MSRPC", "Élevée", "RPC Windows souvent exploité pour la reconnaissance et l'escalade de privilèges."),
            139: ("NetBIOS", "Élevée", "Exposition NetBIOS - risque d'énumération de sessions nulles."),
            443: ("HTTPS", "Faible", "Web sécurisé TLS/SSL."),
            445: ("SMB / CIFS", "Critique", "Partage de fichiers Windows exposé. Cible n°1 de ransomwares (EternalBlue, WannaCry)."),
            1433: ("MSSQL", "Critique", "Base de données SQL Server exposée directement sur le réseau."),
            3306: ("MySQL", "Critique", "Base de données MySQL exposée publiquement. Doit être restreinte au réseau privé."),
            3389: ("RDP", "Critique", "Bureau à distance Windows exposé publiquement. Cible majeure d'attaques par force brute. Exiger VPN + MFA."),
            5432: ("PostgreSQL", "Critique", "Base de données PostgreSQL exposée sur le réseau."),
            5900: ("VNC", "Critique", "Contrôle graphique distant souvent mal authentifié ou non chiffré."),
            6379: ("Redis", "Critique", "Base mémoire sans mot de passe par défaut. Risque de compromission de l'hôte."),
            8080: ("HTTP-Alt", "Moyenne", "Interface d'administration ou serveur d'application à vérifier."),
            27017: ("MongoDB", "Critique", "Base NoSQL sans authentification par défaut dans les configurations basiques."),
        }

        for p_str, proto, state, service, version in port_lines:
            port_num = int(p_str)
            version_str = version.strip() if version else ""
            if port_num in risques_ports:
                s_name, risque, note = risques_ports[port_num]
            else:
                s_name = service
                risque = "Moyenne" if state.lower() == "open" else "Faible"
                note = f"Service {service} actif sur le port {port_num}."

            port_item = {
                "port": port_num,
                "protocole": proto,
                "etat": state,
                "service": s_name,
                "version": version_str,
                "risque": risque,
                "remarque": note,
            }
            ports_analyses.append(port_item)
            if risque in ["Critique", "Élevée"] and state.lower() == "open":
                services_dangereux.append(port_item)

        score_exposition = min(100, len(services_dangereux) * 25 + len(ports_analyses) * 5)

        return jsonify({
            "ok": True,
            "mode": "nmap",
            "os_detecte": os_detecte,
            "total_ports_trouves": len(ports_analyses),
            "ports": ports_analyses,
            "ports_analyses": ports_analyses,
            "services_dangereux": services_dangereux,
            "score_exposition": score_exposition,
            "synthese": (
                f"Système identifié : {os_detecte}. {len(ports_analyses)} port(s) détecté(s), dont {len(services_dangereux)} service(s) à exposition critique ou élevée. "
                + ("Une remédiation immédiate sur le filtrage pare-feu est requise." if services_dangereux else "L'exposition réseau paraît maîtrisée.")
            ),
        })

    else:
        alertes_burp = []
        set_cookie_matches = re.findall(r"(?i)Set-Cookie:\s*([^;\r\n]+)(.*?)(?:\r|\n|$)", raw_text)
        for c_name_val, c_flags in set_cookie_matches:
            c_flags_lower = c_flags.lower()
            c_name = c_name_val.split("=")[0].strip()
            if "secure" not in c_flags_lower:
                alertes_burp.append({"type": "Cookie", "severite": "Élevée", "titre": f"Cookie '{c_name}' sans flag 'Secure'", "desc": "Le cookie peut être transmis en clair sur des connexions HTTP non chiffrées."})
            if "httponly" not in c_flags_lower:
                alertes_burp.append({"type": "Cookie", "severite": "Élevée", "titre": f"Cookie '{c_name}' sans flag 'HttpOnly'", "desc": "Le cookie est accessible via JavaScript document.cookie, vulnérable au vol en cas de faille XSS."})
            if "samesite" not in c_flags_lower:
                alertes_burp.append({"type": "Cookie", "severite": "Moyenne", "titre": f"Cookie '{c_name}' sans attribut 'SameSite'", "desc": "Absence de protection SameSite (Lax ou Strict). Risque accru d'attaque CSRF (Cross-Site Request Forgery)."})

        if re.search(r"^(TRACE|OPTIONS|PUT|DELETE)\s+", raw_text, re.MULTILINE):
            m = re.search(r"^(TRACE|OPTIONS|PUT|DELETE)", raw_text, re.MULTILINE)
            methode = m.group(1)
            if methode == "TRACE":
                alertes_burp.append({"type": "Méthode HTTP", "severite": "Critique", "titre": "Méthode HTTP TRACE activée (XST)", "desc": "Permet des attaques de Cross-Site Tracing (XST) pour contourner les protections HttpOnly."})
            elif methode in ["PUT", "DELETE"]:
                alertes_burp.append({"type": "Méthode HTTP", "severite": "Élevée", "titre": f"Méthode HTTP {methode} exposée", "desc": "Vérifier impérativement que les droits d'écriture et suppression sont strictement restreints et authentifiés."})

        if re.search(r"(?i)(GET|POST)\s+.*?(\?|&)(password|pwd|token|apikey|secret)=", raw_text):
            alertes_burp.append({"type": "Données sensibles dans l'URI", "severite": "Critique", "titre": "Données secrètes transmises dans les paramètres d'URL (GET)", "desc": "Les secrets apparaissent dans les journaux de serveurs, proxys, historique de navigation et en-tête Referer."})

        score_burp = min(100, len(alertes_burp) * 25)
        return jsonify({
            "ok": True,
            "mode": "burp",
            "total_anomalies": len(alertes_burp),
            "score_risque": score_burp,
            "alertes": alertes_burp,
            "findings": alertes_burp,
            "synthese": f"Analyse Burp Suite terminée : {len(alertes_burp)} faiblesse(s) identifiée(s) sur le flux HTTP/SaaS audité.",
        })


# ══════════════════════════════════════════════
#  OUTIL 9 — Audit Bases de Données (PostgreSQL & SQL Server)
# ══════════════════════════════════════════════
@app.route("/api/audit/db-hardening", methods=["POST"])
def audit_db_hardening():
    data = request.get_json() or {}
    db_type = data.get("db_type", "postgres").lower()
    reponses = data.get("reponses", {})

    controles_postgres = [
        {
            "id": "pg_tls",
            "titre": "Chiffrement TLS/SSL obligatoire",
            "desc": "Forcer 'ssl = on' dans postgresql.conf et interdire les connexions non chiffrées dans pg_hba.conf ('hostssl').",
            "impact": "Critique",
            "requete_preuve": "SHOW ssl;\nSELECT * FROM pg_hba_file_rules WHERE type != 'hostssl' AND auth_method != 'reject';"
        },
        {
            "id": "pg_auth",
            "titre": "Authentification SCRAM-SHA-256",
            "desc": "Proscrire les méthodes 'trust' et 'md5'. Utiliser 'scram-sha-256' pour le stockage et l'échange des mots de passe.",
            "impact": "Critique",
            "requete_preuve": "SHOW password_encryption;\nSELECT usename, passwd FROM pg_shadow WHERE passwd NOT LIKE 'SCRAM-SHA-256%';"
        },
        {
            "id": "pg_superuser",
            "titre": "Séparation des rôles & Moindre Privilège",
            "desc": "L'application ne doit JAMAIS se connecter avec le compte superuser 'postgres'. Rôle dédié sans privilèges d'administration.",
            "impact": "Critique",
            "requete_preuve": "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb FROM pg_roles WHERE rolsuper = true;"
        },
        {
            "id": "pg_audit_log",
            "titre": "Journalisation & Pgaudit (Audit Trail)",
            "desc": "Activer la trace des connexions et l'extension 'pgaudit' pour journaliser les requêtes DDL/DML sensibles.",
            "impact": "Élevée",
            "requete_preuve": "SHOW log_connections;\nSHOW log_disconnections;\nSHOW shared_preload_libraries;"
        },
        {
            "id": "pg_network",
            "titre": "Restriction d'écoute réseau (listen_addresses)",
            "desc": "Ne pas écouter sur '*' (0.0.0.0) si la base n'a besoin d'être jointe que localement ou par un sous-réseau applicatif dédié.",
            "impact": "Élevée",
            "requete_preuve": "SHOW listen_addresses;\nSHOW port;"
        },
        {
            "id": "pg_encryption_rest",
            "titre": "Chiffrement des données au repos",
            "desc": "Chiffrement du stockage sous-jacent (LUKS / dm-crypt) ou colonnes sensibles chiffrées via l'extension pgcrypto.",
            "impact": "Élevée",
            "requete_preuve": "SELECT extname, extversion FROM pg_extension WHERE extname = 'pgcrypto';"
        }
    ]

    controles_sqlserver = [
        {
            "id": "ms_tde",
            "titre": "Chiffrement Transparent des Données (TDE)",
            "desc": "Transparent Data Encryption actif sur les bases de production pour protéger les fichiers .mdf, .ndf et sauvegardes .bak.",
            "impact": "Critique",
            "requete_preuve": "SELECT db_name(database_id) AS DB, encryption_state, percent_complete FROM sys.dm_database_encryption_states;"
        },
        {
            "id": "ms_force_enc",
            "titre": "Chiffrement TLS forcé (Force Encryption)",
            "desc": "Configuration TCP/IP avec 'Force Encryption = Yes' et certificat TLS valide.",
            "impact": "Critique",
            "requete_preuve": "SELECT session_id, encrypt_option, auth_scheme, client_net_address FROM sys.dm_exec_connections WHERE session_id = @@SPID;"
        },
        {
            "id": "ms_sa_disabled",
            "titre": "Désactivation ou renommage du compte 'sa'",
            "desc": "Le compte d'administration 'sa' (System Administrator) doit être désactivé avec un mot de passe complexe non utilisé par les applications.",
            "impact": "Critique",
            "requete_preuve": "SELECT name, is_disabled, create_date, modify_date FROM sys.server_principals WHERE sid = 0x01;"
        },
        {
            "id": "ms_auth_mode",
            "titre": "Authentification Windows Intégrée (Active Directory)",
            "desc": "Privilégier l'authentification Windows / Kerberos plutôt que l'authentification SQL locale pour appliquer la politique de domaine.",
            "impact": "Élevée",
            "requete_preuve": "SELECT SERVERPROPERTY('IsIntegratedSecurityOnly') AS [1=Windows_Only, 0=Mixed_Mode];"
        },
        {
            "id": "ms_xp_cmdshell",
            "titre": "Désactivation de la procédure étendue xp_cmdshell",
            "desc": "xp_cmdshell permet d'exécuter des commandes OS depuis SQL et doit être formellement désactivée dans sys.configurations.",
            "impact": "Critique",
            "requete_preuve": "SELECT name, value, value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';"
        },
        {
            "id": "ms_audit_spec",
            "titre": "Audit SQL Server & Journalisation des privilèges",
            "desc": "Spécification d'audit active consignant les modifications de schéma, les accès sysadmin et échecs d'authentification.",
            "impact": "Élevée",
            "requete_preuve": "SELECT name, is_state_enabled, queue_delay FROM sys.server_audits;"
        }
    ]

    controles = controles_postgres if db_type == "postgres" else controles_sqlserver
    reponses = data.get("reponses", {})
    if isinstance(data.get("checked_items"), list):
        for cid in data.get("checked_items"):
            reponses[cid] = True

    score_obtenu = 0
    total_points = len(controles) * 10
    bilan = []

    for c in controles:
        statut = reponses.get(c["id"], False)
        pts = 10 if statut else 0
        score_obtenu += pts
        bilan.append({
            **c,
            "conforme": statut,
            "statut_texte": "CONFORME" if statut else "NON CONFORME",
        })

    pourcentage = round((score_obtenu / total_points) * 100, 1) if total_points else 0
    manquants = [b for b in bilan if not b["conforme"]]

    if pourcentage >= 90:
        niveau = "EXCELLENT"
        couleur = "vert"
        synthese = f"Durcissement remarquable de l'instance {db_type.upper()}. Conforme aux meilleures pratiques CIS Benchmark et ISO 27001."
    elif pourcentage >= 65:
        niveau = "ACCEPTABLE"
        couleur = "jaune"
        synthese = f"Niveau de sécurité convenable mais des contrôles critiques demeurent non conformes sur {db_type.upper()}."
    else:
        niveau = "NON CONFORME / RISQUE ÉLEVÉ"
        couleur = "rouge"
        synthese = f"Faiblesses majeures de durcissement sur {db_type.upper()}. Risque accru de compromission des données ou d'accès non autorisé."

    return jsonify({
        "ok": True,
        "db_type": db_type,
        "score": pourcentage,
        "conformite_pct": pourcentage,
        "valides": int(score_obtenu / 10),
        "total": len(controles),
        "statut": niveau,
        "niveau": niveau,
        "couleur": couleur,
        "synthese": synthese,
        "points_audit": bilan,
        "manquants": manquants,
        "norme_ref": "ISO/IEC 27001:2022 A.8.11 & A.8.24 / CIS Database Benchmark"
    })


# ══════════════════════════════════════════════
#  OUTIL 10 — Gestion des Risques EBIOS RM (ANSSI)
# ══════════════════════════════════════════════
@app.route("/api/audit/ebios", methods=["POST"])
def audit_ebios():
    data = request.get_json() or {}
    scenarios = data.get("scenarios", [])

    if not scenarios:
        scenarios = [
            {
                "actif": "Base de Données Clients (CRM / SaaS B2B)",
                "menace": "Cybercriminel (Ransomware / Exfiltration SQLi)",
                "vraisemblance": 3,
                "gravite": 4,
                "mesure": "Chiffrement TDE, sauvegardes immuables hors-ligne, EDR et requêtes préparées"
            },
            {
                "actif": "Portail d'Authentification Collaborateurs (SSO)",
                "menace": "Phishing / Credential Stuffing",
                "vraisemblance": 4,
                "gravite": 3,
                "mesure": "MFA obligatoire avec clé FIDO2, politique d'accès conditionnel"
            },
            {
                "actif": "Code Source & Pipeline CI/CD",
                "menace": "Attaque Supply Chain / Développeur malveillant",
                "vraisemblance": 2,
                "gravite": 3,
                "mesure": "Signature des commits, SAST/DAST automatisé, revue par les pairs obligatoire"
            },
            {
                "actif": "Infrastructure Cloud (AWS / Azure)",
                "menace": "Mauvaise configuration des droits IAM",
                "vraisemblance": 3,
                "gravite": 3,
                "mesure": "Audit CSPM continu, principe du moindre privilège, suppression des clés permanentes"
            }
        ]

    evaluations = []
    critiques_count = 0
    eleves_count = 0

    for s in scenarios:
        v = int(s.get("vraisemblance", 2))
        g = int(s.get("gravite", 2))
        produit = v * g

        if produit >= 12:
            niveau_risque = "Critique"
            couleur = "rouge"
            critiques_count += 1
            action = "Traitement prioritaire immédiat requis (Plan d'action d'urgence)"
        elif produit >= 8:
            niveau_risque = "Élevé"
            couleur = "orange"
            eleves_count += 1
            action = "Réduction active du risque sous 30 jours"
        elif produit >= 4:
            niveau_risque = "Modéré"
            couleur = "jaune"
            action = "Surveillance et application des contrôles de sécurité standards"
        else:
            niveau_risque = "Faible"
            couleur = "vert"
            action = "Risque accepté avec maintien des mesures existantes"

        evaluations.append({
            "actif": s.get("actif", "Actif non spécifié"),
            "menace": s.get("menace", "Menace indéterminée"),
            "vraisemblance": v,
            "gravite": g,
            "score_brut": produit,
            "niveau_risque": niveau_risque,
            "couleur": couleur,
            "action_recommandee": action,
            "mesure_existante": s.get("mesure", "Aucune mesure documentée"),
        })

    matrice = {}
    moderes_count = 0
    faibles_count = 0
    for e in evaluations:
        key = f"{e['gravite']}-{e['vraisemblance']}"
        matrice[key] = matrice.get(key, 0) + 1
        if 4 <= e['score_brut'] < 8:
            moderes_count += 1
        elif e['score_brut'] < 4:
            faibles_count += 1

    return jsonify({
        "ok": True,
        "methode": "EBIOS Risk Manager (ANSSI) & ISO/IEC 27005",
        "total": len(evaluations),
        "total_scenarios": len(evaluations),
        "critiques": critiques_count,
        "nb_critiques": critiques_count,
        "eleves": eleves_count,
        "nb_eleves": eleves_count,
        "moderes": moderes_count,
        "faibles": faibles_count,
        "matrice": matrice,
        "resultats": evaluations,
        "scenarios_evalues": evaluations,
        "synthese_auditeur": f"Cartographie EBIOS RM : {len(evaluations)} scénario(s) analysé(s). {critiques_count} risque(s) critique(s) et {eleves_count} risque(s) élevé(s) identifié(s) nécessitant un arbitrage dans le SMSI."
    })


# Point d'entrée pour Vercel (WSGI handler)
# Vercel importe automatiquement la variable `app`

