from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, validator
import sqlite3
import re
import hashlib
import secrets
import hmac
import json
import user_agents
from datetime import datetime
from typing import Optional, List
import os

# ==================== INITIALIZATION ====================
app = FastAPI(title="Threat Protection System")

# Setup templates
templates = Jinja2Templates(directory="templates")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ==================== DATABASE SETUP ====================
DB_FILE = "threat_protection.db"

def init_database():
    """Create tables if they don't exist"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            is_email_valid INTEGER DEFAULT 0,
            threat_score INTEGER DEFAULT 0,
            threat_details TEXT DEFAULT '',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            last_login TEXT
        )
    ''')
    
    # Create threat_logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            threat_type TEXT NOT NULL,
            threat_score INTEGER NOT NULL,
            details TEXT,
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Create typing_sessions table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS typing_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_type TEXT NOT NULL,
            sentence TEXT NOT NULL,
            time_taken REAL NOT NULL,
            typed_text TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create user_devices table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS user_devices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            device_fingerprint TEXT NOT NULL,
            device_info TEXT,
            ip_address TEXT,
            location TEXT,
            first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
            last_seen TEXT DEFAULT CURRENT_TIMESTAMP,
            is_trusted INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create behavioral_data table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS behavioral_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            session_id TEXT,
            mouse_movements TEXT,
            key_timings TEXT,
            scroll_data TEXT,
            time_of_day INTEGER,
            day_of_week INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    conn.commit()
    conn.close()
    print("✅ Database initialized successfully with all tables!")

# Initialize database on startup
init_database()

# ==================== HELPER FUNCTIONS ====================
def get_db_connection():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password: str):
    """Hash password with salt"""
    salt = secrets.token_hex(16)
    hash_obj = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}${hash_obj.hex()}"

def verify_password(plain_password, hashed_password):
    """Verify password against hash"""
    try:
        salt, hash_value = hashed_password.split('$')
        new_hash = hashlib.pbkdf2_hmac('sha256', plain_password.encode(), salt.encode(), 100000)
        return hmac.compare_digest(new_hash.hex(), hash_value)
    except:
        return False

def check_email_threat(email: str):
    """
    Check email for threats
    Returns: (is_valid, threat_score, threat_details)
    """
    threat_score = 0
    threat_details = []
    
    # List of disposable email domains
    disposable_domains = [
        'tempmail.com', 'throwaway.com', 'mailinator.com', 'guerrillamail.com',
        'sharklasers.com', 'yopmail.com', 'temp-mail.org', 'fakeinbox.com',
        '10minutemail.com', 'burnermail.io', 'guerrillamail.net'
    ]
    
    domain = email.split('@')[1].lower()
    
    # Check for disposable domains
    if domain in disposable_domains:
        threat_score += 50
        threat_details.append("Disposable email domain detected")
    
    # Check for suspicious patterns
    if re.match(r'test\d*@', email.lower()) or re.match(r'user\d*@', email.lower()):
        threat_score += 30
        threat_details.append("Suspicious email pattern detected")
    
    # Check for known malicious domains
    malicious_domains = ['hacker.com', 'malicious.com', 'phishing.com', 'spam.com']
    if domain in malicious_domains:
        threat_score += 100
        threat_details.append("Known malicious domain detected")
    
    # Check for system emails
    if email.startswith('admin@') or email.startswith('root@') or email.startswith('postmaster@'):
        threat_score += 40
        threat_details.append("System email pattern detected")
    
    # Email is valid if threat score < 70
    is_valid = threat_score < 70
    
    return is_valid, threat_score, ", ".join(threat_details) if threat_details else "Clean email"

def check_password_strength(password: str):
    """Check password strength"""
    score = 0
    feedback = []
    
    if len(password) >= 8:
        score += 25
    else:
        feedback.append("Too short")
    
    if re.search(r'[A-Z]', password):
        score += 25
    else:
        feedback.append("No uppercase")
    
    if re.search(r'\d', password):
        score += 25
    else:
        feedback.append("No numbers")
    
    if re.search(r'[!@#$%^&*]', password):
        score += 25
    else:
        feedback.append("No special chars")
    
    return min(score, 100), ", ".join(feedback) if feedback else "Strong password"

def generate_device_fingerprint(request: Request, email: str = ""):
    """Generate a unique device fingerprint"""
    user_agent = request.headers.get("user-agent", "Unknown")
    accept_language = request.headers.get("accept-language", "Unknown")
    accept_encoding = request.headers.get("accept-encoding", "Unknown")
    
    # Get client IP
    ip_address = request.client.host if request.client else "Unknown"
    
    # Create fingerprint
    fingerprint_string = f"{email}|{ip_address}|{user_agent}|{accept_language}|{accept_encoding}"
    fingerprint = hashlib.sha256(fingerprint_string.encode()).hexdigest()
    
    return fingerprint

def log_suspicious_activity(email: str, activity_type: str, details: any):
    """Log suspicious activity to database"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO threat_logs (email, threat_type, threat_score, details)
            VALUES (?, ?, ?, ?)
        ''', (email, activity_type, 50, str(details)))
        
        conn.commit()
        print(f"⚠️ Suspicious activity logged: {email} - {activity_type}")
    except Exception as e:
        print(f"Error logging suspicious activity: {e}")
    finally:
        conn.close()

def get_client_info(request: Request):
    """Extract client information from request"""
    # Get IP address
    ip_address = request.client.host if request.client else "Unknown"
    
    # Simple location (you can integrate with ip-api.com for real location)
    location = "Unknown"
    
    # Get user agent
    user_agent_string = request.headers.get("user-agent", "Unknown")
    
    # Parse user agent
    try:
        user_agent = user_agents.parse(user_agent_string)
        device_info = {
            "device": user_agent.device.family,
            "browser": user_agent.browser.family,
            "browser_version": user_agent.browser.version_string,
            "os": user_agent.os.family,
            "os_version": user_agent.os.version_string,
            "is_mobile": user_agent.is_mobile,
            "is_tablet": user_agent.is_tablet,
            "is_pc": user_agent.is_pc
        }
    except:
        device_info = {
            "device": "Unknown",
            "browser": "Unknown",
            "os": "Unknown"
        }
    
    return {
        "ip_address": ip_address,
        "location": location,
        "device_info": json.dumps(device_info)
    }

# List of random sentences for typing test
TYPING_SENTENCES = [
    "The quick brown fox jumps over the lazy dog near the river bank.",
    "Pack my box with five dozen liquor jugs for the party tonight.",
    "How razorback-jumping frogs can level six piqued gymnasts quickly.",
    "The five boxing wizards jump quickly while sipping coffee.",
    "When zombies arrive quickly fax Judge Pat and watch her craft.",
    "Crazy Fredrick bought many very exquisite opal jewels from the king.",
    "We promptly judged antique ivory buckles for the next prize.",
    "A wizard's job is to vex chumps quickly in foggy weather.",
    "The jay pig fox zebra and my wolves quack in the sun.",
    "Sphinx of black quartz judge my vow and grant me access.",
    "Two driven jocks help fax my big quiz during lunch break.",
    "My ex pub quiz crowd gave joyful thanks for the win.",
    "The vixen jumped quickly on her foe barking with zeal.",
    "Five quacking zephyrs jolt my wax bed beneath the tree.",
    "Amazingly few discotheques provide jukeboxes for my party place.",
    "Cozy lummox gives smart squid who asks for job pen.",
    "The wizard quickly jinxed the gnomes before they vaporized.",
    "Grumpy wizards make a toxic brew for the evil queen.",
    "Jaded zombies acted quaintly but kept driving their oxen forward.",
    "The quick onyx goblin jumps over the lazy dwarf in the cave."
]

def get_random_sentences(count=5):
    """Get random sentences for typing test"""
    import random
    return random.sample(TYPING_SENTENCES, min(count, len(TYPING_SENTENCES)))

# ==================== PYDANTIC MODELS ====================
class UserCreate(BaseModel):
    email: EmailStr
    password: str
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not any(char.isdigit() for char in v):
            raise ValueError('Password must contain at least one number')
        if not any(char.isupper() for char in v):
            raise ValueError('Password must contain at least one uppercase letter')
        return v

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class TypingData(BaseModel):
    email: str
    sentence: str
    time_taken: float
    typed_text: str
    mouse_movements: Optional[List] = None
    key_timings: Optional[List] = None
    scroll_data: Optional[List] = None

# ==================== HTML PAGE ROUTES ====================
@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

# ==================== API ENDPOINTS ====================

@app.get("/api/typing-sentences")
async def get_typing_sentences():
    """Get random sentences for typing test"""
    sentences = get_random_sentences(1)  # Just return 1 sentence
    return {"sentences": sentences}

@app.post("/api/register")
async def register(user: UserCreate, request: Request):
    """Register a new user"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if user exists
        cursor.execute("SELECT * FROM users WHERE email = ?", (user.email,))
        existing_user = cursor.fetchone()
        if existing_user:
            return JSONResponse(
                status_code=400,
                content={"detail": "User already exists"}
            )
        
        # Check email threat
        is_valid, threat_score, threat_details = check_email_threat(user.email)
        
        # Create user
        hashed = hash_password(user.password)
        cursor.execute('''
            INSERT INTO users (email, hashed_password, is_email_valid, threat_score, threat_details)
            VALUES (?, ?, ?, ?, ?)
        ''', (user.email, hashed, 1 if is_valid else 0, threat_score, threat_details))
        
        # Get user ID
        cursor.execute("SELECT id FROM users WHERE email = ?", (user.email,))
        user_id = cursor.fetchone()["id"]
        
        # Log threat if detected
        if threat_score > 30:
            cursor.execute('''
                INSERT INTO threat_logs (email, threat_type, threat_score, details)
                VALUES (?, ?, ?, ?)
            ''', (user.email, "Email Threat", threat_score, threat_details))
        
        # Record device
        fingerprint = generate_device_fingerprint(request, user.email)
        client_info = get_client_info(request)
        
        cursor.execute('''
            INSERT INTO user_devices 
            (user_id, device_fingerprint, device_info, ip_address, location, is_trusted)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, fingerprint, client_info["device_info"], 
              client_info["ip_address"], client_info["location"], 1))
        
        conn.commit()
        
        # Get created user
        cursor.execute("SELECT * FROM users WHERE email = ?", (user.email,))
        new_user = cursor.fetchone()
        
        return {
            "id": new_user["id"],
            "email": new_user["email"],
            "is_email_valid": bool(new_user["is_email_valid"]),
            "threat_score": new_user["threat_score"],
            "threat_details": new_user["threat_details"],
            "created_at": new_user["created_at"],
            "message": "Registration successful"
        }
        
    except Exception as e:
        print(f"Error: {e}")
        return JSONResponse(
            status_code=500,
            content={"detail": str(e)}
        )
    finally:
        if conn:
            conn.close()

@app.post("/api/register-typing")
async def register_typing(request: Request):
    """Save typing data and location during registration"""
    try:
        data = await request.json()
        email = data.get("email")
        location = data.get("location", {})
        device_info = data.get("device_info", {})
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get user ID
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        
        if not user:
            return JSONResponse(status_code=404, content={"detail": "User not found"})
        
        user_id = user["id"]
        
        # Save typing session (existing code)
        cursor.execute('''
            INSERT INTO typing_sessions 
            (user_id, session_type, sentence, time_taken, typed_text)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, "registration", data.get("sentence"), 
              data.get("time_taken"), data.get("typed_text")))
        
        # Save device with detailed location
        fingerprint = device_info.get("fingerprint", "unknown")
        
        cursor.execute('''
            INSERT INTO user_devices 
            (user_id, device_fingerprint, device_info, ip_address, location, is_trusted)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            user_id, 
            fingerprint, 
            json.dumps(device_info),
            location.get("ip", "Unknown"),
            json.dumps(location),
            1  # trusted = first device
        ))
        
        conn.commit()
        conn.close()
        
        return {"success": True, "message": "Registration data saved"}
        
    except Exception as e:
        print(f"Error saving typing data: {e}")
        return JSONResponse(status_code=500, content={"detail": str(e)})

@app.post("/api/login")
async def login(user: UserLogin, request: Request):
    """Login user"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Find user
        cursor.execute("SELECT * FROM users WHERE email = ?", (user.email,))
        db_user = cursor.fetchone()
        
        if not db_user:
            return {
                "access_granted": False,
                "message": "User not found"
            }
        
        # Verify password
        if not verify_password(user.password, db_user["hashed_password"]):
            # Log failed attempt
            cursor.execute('''
                INSERT INTO threat_logs (email, threat_type, threat_score, details)
                VALUES (?, ?, ?, ?)
            ''', (user.email, "Failed Login", 20, "Incorrect password"))
            conn.commit()
            
            return {
                "access_granted": False,
                "message": "Invalid password"
            }
        
        # Update last login
        cursor.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE email = ?", (user.email,))
        
        # Record device
        fingerprint = generate_device_fingerprint(request, user.email)
        client_info = get_client_info(request)
        
        cursor.execute('''
            INSERT OR REPLACE INTO user_devices 
            (user_id, device_fingerprint, device_info, ip_address, location, last_seen)
            VALUES ((SELECT id FROM users WHERE email = ?), ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (user.email, fingerprint, client_info["device_info"], 
              client_info["ip_address"], client_info["location"]))
        
        conn.commit()
        
        return {
            "access_granted": True,
            "message": "Login successful",
            "user": {
                "id": db_user["id"],
                "email": db_user["email"],
                "is_email_valid": bool(db_user["is_email_valid"]),
                "threat_score": db_user["threat_score"],
                "threat_details": db_user["threat_details"],
                "created_at": db_user["created_at"],
                "last_login": db_user["last_login"]
            }
        }
        
    except Exception as e:
        print(f"Error: {e}")
        return JSONResponse(
            status_code=500,
            content={"detail": str(e)}
        )
    finally:
        if conn:
            conn.close()

@app.post("/api/login-verify")
async def login_verify(request: Request):
    """Verify login with typing speed and behavioral data"""
    try:
        data = await request.json()
        email = data.get("email")
        time_taken = data.get("time_taken")
        behavioral_data = data.get("behavioral_data", {})
        
        # Check if typing time is between 25-45 seconds
        if time_taken < 25 or time_taken > 45:
            # Log suspicious attempt
            log_suspicious_activity(email, "unusual_typing_speed", time_taken)
            return {"verified": False, "reason": "speed", "message": "Typing speed anomaly detected"}
        
        # Get user's historical data
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Get user ID
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return {"verified": False, "reason": "user_not_found"}
        
        user_id = user["id"]
        
        # Check if device is known
        device_fingerprint = generate_device_fingerprint(request, email)
        cursor.execute('''
            SELECT * FROM user_devices 
            WHERE user_id = ? AND device_fingerprint = ?
        ''', (user_id, device_fingerprint))
        
        known_device = cursor.fetchone()
        
        # Save this login attempt
        cursor.execute('''
            INSERT INTO typing_sessions 
            (user_id, session_type, sentence, time_taken)
            VALUES (?, ?, ?, ?)
        ''', (user_id, "login", data.get("sentence", ""), time_taken))
        
        conn.commit()
        conn.close()
        
        if not known_device:
            # New device - log for review
            log_suspicious_activity(email, "new_device", device_fingerprint)
            return {"verified": True, "known_device": False, "warning": "New device detected"}
        
        return {"verified": True, "known_device": True}
        
    except Exception as e:
        print(f"Error in login verify: {e}")
        return JSONResponse(status_code=500, content={"detail": str(e)})

@app.get("/api/check-email/{email}")
async def check_email(email: str):
    """Check email threat level"""
    is_valid, score, details = check_email_threat(email)
    return {
        "email": email,
        "is_valid": is_valid,
        "threat_score": score,
        "threat_details": details
    }

@app.get("/api/users")
async def get_users():
    """Get all users"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, email, is_email_valid, threat_score, threat_details, created_at FROM users")
    users = cursor.fetchall()
    conn.close()
    return [dict(user) for user in users]

@app.get("/api/threat-logs")
async def get_threat_logs():
    """Get all threat logs"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threat_logs ORDER BY timestamp DESC")
    logs = cursor.fetchall()
    conn.close()
    return [dict(log) for log in logs]

@app.get("/api/user-devices/{email}")
async def get_user_devices(email: str):
    """Get devices for a user"""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        SELECT d.* FROM user_devices d
        JOIN users u ON d.user_id = u.id
        WHERE u.email = ?
        ORDER BY d.last_seen DESC
    ''', (email,))
    devices = cursor.fetchall()
    conn.close()
    return [dict(device) for device in devices]

if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*60)
    print("🚀 Threat Protection System Starting...")
    print("="*60)
    print("\n📱 Access your app at: http://localhost:8000")
    print("📚 API Documentation: http://localhost:8000/docs")
    print("🔍 Check users: http://localhost:8000/api/users")
    print("🔍 Check threat logs: http://localhost:8000/api/threat-logs")
    print("="*60 + "\n")
    
    # Check if templates folder exists
    if not os.path.exists("templates"):
        os.makedirs("templates")
        print("📁 Created templates folder - please add your HTML files")
    
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=True)