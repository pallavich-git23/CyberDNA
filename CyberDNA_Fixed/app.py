import os
import requests
from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3, os, re
import ipaddress
import json
from urllib.parse import urlsplit
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "local-demo-change-me")
DB = os.path.join(os.path.dirname(__file__), "cyberdna.db")
DEMO_USER, DEMO_PASS = "cyberdna", "CyberDNA@123"

def connect():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    with connect() as db:
        db.execute("""CREATE TABLE IF NOT EXISTS scans(
            id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL,
            scan_type TEXT NOT NULL, risk TEXT NOT NULL, finding TEXT NOT NULL,
            created_at TEXT NOT NULL)""")
        if db.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 0:
            now = datetime.now()
            demo = [
                ("192.168.1.12","IP Address","High","Repeated suspicious connection attempts",now-timedelta(hours=1)),
                ("https://example-suspicious.test/login","URL","Medium","URL contains a suspicious login pattern",now-timedelta(hours=3)),
                ("8.8.8.8","IP Address","Low","No local demo rules matched",now-timedelta(days=1)),
                ("invoice_update.exe","File Name","High","Demo rule matched a risky executable extension",now-timedelta(days=2)),
                ("mail.example.test","Domain","Medium","Domain needs further investigation",now-timedelta(days=3)),
                ("203.0.113.42","IP Address","Low","No local demo rules matched",now-timedelta(days=4)),
                ("https://example.test","URL","Low","No local demo rules matched",now-timedelta(days=5))]
            for target, kind, risk, finding, stamp in demo:
                db.execute("INSERT INTO scans(target,scan_type,risk,finding,created_at) VALUES(?,?,?,?,?)",
                           (target,kind,risk,finding,stamp.strftime("%Y-%m-%d %H:%M")))

def login_required(fn):
    @wraps(fn)
    def inner(*args, **kwargs):
        if not session.get("logged_in"): return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return inner

def get_scans(limit=None):
    with connect() as db:
        sql="SELECT * FROM scans ORDER BY id DESC"
        return db.execute(sql + (" LIMIT ?" if limit else ""), (limit,) if limit else ()).fetchall()

def counts():
    with connect() as db:
        return {"total":db.execute("SELECT COUNT(*) FROM scans").fetchone()[0],
                "high":db.execute("SELECT COUNT(*) FROM scans WHERE risk='High'").fetchone()[0],
                "medium":db.execute("SELECT COUNT(*) FROM scans WHERE risk='Medium'").fetchone()[0],
                "low":db.execute("SELECT COUNT(*) FROM scans WHERE risk='Low'").fetchone()[0]}

@app.route("/")
def index(): return redirect(url_for("dashboard") if session.get("logged_in") else url_for("login"))

@app.route("/login", methods=["GET","POST"])
def login():
    if session.get("logged_in"): return redirect(url_for("dashboard"))
    if request.method=="POST":
        if request.form.get("username","").strip()==DEMO_USER and request.form.get("password","")==DEMO_PASS:
            session["logged_in"]=True
            return redirect(url_for("dashboard"))
        flash("Incorrect login. Use the demo credentials shown below.", "error")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    with connect() as db:
        daily = db.execute("""
            SELECT substr(created_at, 1, 10) AS day,
                   COUNT(*) AS total
            FROM scans
            GROUP BY day
            ORDER BY day DESC
            LIMIT 7
        """).fetchall()

    daily = list(reversed(daily))

    daily_labels = [row["day"] for row in daily]
    daily_totals = [row["total"] for row in daily]

    return render_template(
        "dashboard.html",
        scans=get_scans(6),
        counts=counts(),
        daily=daily,
        daily_labels=daily_labels,
        daily_totals=daily_totals
    )

@app.route("/scan", methods=["GET","POST"])
@login_required
def scan():
    result=None
    if request.method=="POST":
        target=request.form.get("target","").strip()
        kind=request.form.get("scan_type","URL")
        if not target: flash("Please enter an indicator.", "error")
        else:
            lower=target.lower()
            if any(w in lower for w in ("malware","phish","suspicious","ransom","evil")) or target.endswith((".exe",".bat",".ps1")):
                risk,finding="High","A local demo rule matched a suspicious keyword or executable extension"
            elif any(w in lower for w in ("login","verify","update","secure")):
                risk,finding="Medium","Review for possible impersonation or unusual behavior"
            else: risk,finding="Low","No suspicious patterns matched the local demo rules"
            created=datetime.now().strftime("%Y-%m-%d %H:%M")
            with connect() as db:
                db.execute("INSERT INTO scans(target,scan_type,risk,finding,created_at) VALUES(?,?,?,?,?)",(target,kind,risk,finding,created))
            result={"target":target,"risk":risk,"finding":finding}
    return render_template("scan.html", result=result)


def analyze_ioc(value):
    value = value.strip()

    if not value:
        return {
            "valid": False,
            "ioc": value,
            "ioc_type": "Unknown",
            "risk": "Invalid",
            "score": 0,
            "findings": ["Please enter an indicator."]
        }

    # Check IP address
    try:
        ip = ipaddress.ip_address(value)
        details = []

        if ip.is_private:
            details.append("Private IP address.")
        elif ip.is_loopback:
            details.append("Loopback IP address.")
        else:
            details.append(
                "IP format is valid; reputation has not been checked."
            )

        return {
            "valid": True,
            "ioc": value,
            "ioc_type": f"IPv{ip.version} address",
            "risk": "Unverified",
            "score": None,
            "findings": details
        }
    except ValueError:
        pass

    # Check file hash
    hashes = {
        32: "MD5 hash",
        40: "SHA-1 hash",
        64: "SHA-256 hash"
    }

    if len(value) in hashes and re.fullmatch(r"[a-fA-F0-9]+", value):
        return {
            "valid": True,
            "ioc": value.lower(),
            "ioc_type": hashes[len(value)],
            "risk": "Unverified",
            "score": None,
            "findings": [
                "Hash format is valid.",
                "File reputation has not been checked."
            ]
        }

    # Check URL
    if re.match(r"(?i)^https?://", value):
        try:
            parsed = urlsplit(value)
            if not parsed.hostname or not parsed.netloc:
                raise ValueError("Invalid URL")

            _ = parsed.port
            score = 0
            findings = []

            if parsed.scheme.lower() == "http":
                score += 15
                findings.append("URL uses unencrypted HTTP.")

            if any(
                word in parsed.path.lower()
                for word in ("login", "verify", "password", "account")
            ):
                score += 10
                findings.append("URL path contains a credential-related term.")

            risk = (
                "High" if score >= 50
                else "Medium" if score >= 25
                else "Low"
            )

            findings.append(
                "Heuristic assessment only; no live reputation check was performed."
            )

            return {
                "valid": True,
                "ioc": value,
                "ioc_type": "URL",
                "risk": risk,
                "score": score,
                "findings": findings
            }
        except ValueError:
            return {
                "valid": False,
                "ioc": value,
                "ioc_type": "URL",
                "risk": "Invalid",
                "score": 0,
                "findings": ["Invalid URL format."]
            }

    # Check basic domain format
    domain = value.rstrip(".").lower()
    labels = domain.split(".")

    if (
        len(domain) <= 253
        and len(labels) >= 2
        and all(
            re.fullmatch(
                r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?",
                label
            )
            and len(label) <= 63
            for label in labels
        )
        and labels[-1].isalpha()
        and len(labels[-1]) >= 2
    ):
        return {
            "valid": True,
            "ioc": domain,
            "ioc_type": "Domain",
            "risk": "Unverified",
            "score": None,
            "findings": [
                "Domain format is valid.",
                "DNS and threat reputation have not been checked."
            ]
        }

    return {
        "valid": False,
        "ioc": value,
        "ioc_type": "Unknown",
        "risk": "Invalid",
        "score": 0,
        "findings": [
            "Unsupported format. Enter an IP, URL, domain, or file hash."
        ]
    }

@app.route("/ioc-analyzer", methods=["GET", "POST"])
@login_required
def ioc_analyzer():
    result = None
    error = None
    submitted_ioc = ""

    # Create a separate history table without changing existing tables.
    with connect() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS ioc_scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                risk TEXT NOT NULL,
                score INTEGER,
                findings TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)

    if request.method == "POST":
        submitted_ioc = request.form.get("ioc", "").strip()

        if len(submitted_ioc) > 2048:
            error = "Input is too long. Please use 2048 characters or fewer."
        else:
            result = analyze_ioc(submitted_ioc)

            # Save the analysis, including invalid inputs, for demonstration.
            with connect() as db:
                db.execute("""
                    INSERT INTO ioc_scans
                    (ioc, ioc_type, risk, score, findings)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    result["ioc"],
                    result["ioc_type"],
                    result["risk"],
                    result["score"],
                    json.dumps(result["findings"])
                ))

    with connect() as db:
        history = db.execute("""
            SELECT id, ioc, ioc_type, risk, score, created_at
            FROM ioc_scans
            ORDER BY id DESC
            LIMIT 10
        """).fetchall()

    return render_template(
        "ioc_analyzer.html",
        result=result,
        error=error,
        submitted_ioc=submitted_ioc,
        history=history
    )


@app.route("/history")
@login_required
def history():
    q=request.args.get("q","").strip()
    with connect() as db:
        rows=db.execute("SELECT * FROM scans WHERE target LIKE ? OR finding LIKE ? ORDER BY id DESC",(f"%{q}%",f"%{q}%")).fetchall()
    return render_template("history.html", scans=rows, query=q)



@app.route("/threat-intelligence")
@login_required
def threat_intelligence():
    # Demo threat intelligence records.
    # These are sample records, not live threat feed results.
    threats = [
        {
            "ipAddress": "198.51.100.24",
            "abuseConfidenceScore": 95,
            "totalReports": 42,
            "countryCode": "US",
            "usageType": "Data Center/Web Hosting",
            "lastReportedAt": "2026-10-18T10:30:00+00:00"
        },
        {
            "ipAddress": "203.0.113.45",
            "abuseConfidenceScore": 87,
            "totalReports": 27,
            "countryCode": "GB",
            "usageType": "Data Center/Web Hosting",
            "lastReportedAt": "2026-10-17T14:15:00+00:00"
        },
        {
            "ipAddress": "192.0.2.88",
            "abuseConfidenceScore": 72,
            "totalReports": 16,
            "countryCode": "IN",
            "usageType": "Unknown",
            "lastReportedAt": "2026-10-16T08:45:00+00:00"
        }
    ]

    return render_template(
        "threat_intelligence.html",
        threats=threats,
        error=None,
        demo_mode=True
    )

@app.route("/reports")
@login_required
def reports(): return render_template("reports.html", counts=counts(), scans=get_scans())

@app.route("/profile")
@login_required
def profile(): return render_template("profile.html")

if __name__=="__main__":
    init_db()
    app.run(debug=True)
