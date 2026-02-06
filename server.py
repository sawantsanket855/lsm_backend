from fastapi import FastAPI, APIRouter, HTTPException, Depends, Form
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from starlette.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from pathlib import Path
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from psycopg2.pool import SimpleConnectionPool
import psycopg2, psycopg2.extras
import os, time

from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import jwt, JWTError
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

# ==================== ENV & APP ====================
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")



SECRET_KEY = os.getenv("JWT_SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

app = FastAPI(title="LMS API", version="1.0.0")

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request, exc):
    print(f"Validation Error: {exc.errors()}")
    detail = []
    for error in exc.errors():
        loc = " -> ".join([str(l) for l in error.get("loc", [])])
        msg = error.get("msg")
        detail.append(f"{loc}: {msg}")
    return JSONResponse(
        status_code=422,
        content={"detail": ", ".join(detail), "body": str(exc.body)},
    )
api_router = APIRouter(prefix="/api")

security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ==================== DB POOL ====================
pool = SimpleConnectionPool(
    1, 20,
    host=os.getenv("POSTGRES_HOST"),
    port=os.getenv("POSTGRES_PORT"),
    dbname=os.getenv("POSTGRES_DB"),
    user=os.getenv("POSTGRES_USER"),
    password=os.getenv("POSTGRES_PASSWORD")
)

def get_db():
    conn = pool.getconn()
    try:
        yield conn
    finally:
        pool.putconn(conn)

TABLE_SCHEMAS = {
    "users": """
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            role TEXT DEFAULT 'student',
            profile JSONB DEFAULT '{"bio": "", "avatar": null}'::jsonb,
            interests JSONB DEFAULT '[]'::jsonb,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """,
    "courses": """
        CREATE TABLE IF NOT EXISTS courses (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT,
            category TEXT,
            difficulty TEXT,
            tags JSONB,
            modules JSONB DEFAULT '[]'::jsonb,
            thumbnail TEXT,
            created_by TEXT,
            created_at TIMESTAMP,
            is_published BOOLEAN DEFAULT FALSE
        )
    """,
    "sessions": """
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            course_id TEXT REFERENCES courses(id) ON DELETE CASCADE,
            module_id TEXT NOT NULL,
            name TEXT NOT NULL,
            duration_minutes INTEGER DEFAULT 0,
            content_type TEXT NOT NULL,
            content_url TEXT,
            content_text TEXT,
            quiz_id TEXT,
            is_document_available BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """,
    "notifications": """
        CREATE TABLE IF NOT EXISTS notifications (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            message TEXT NOT NULL,
            type TEXT NOT NULL,
            read BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """,
    "learning_paths": """
        CREATE TABLE IF NOT EXISTS learning_paths (
            id TEXT PRIMARY KEY,
            title TEXT NOT NULL,
            description TEXT,
            course_ids JSONB DEFAULT '[]'::jsonb,
            target_interests JSONB DEFAULT '[]'::jsonb,
            created_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """,
    "progress": """
        CREATE TABLE IF NOT EXISTS progress (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            course_id TEXT NOT NULL,
            module_id TEXT NOT NULL,
            completed BOOLEAN DEFAULT FALSE,
            time_spent INTEGER DEFAULT 0,
            completed_at TIMESTAMP,
            UNIQUE(user_id, module_id)
        )
    """,
    "quizzes": """
        CREATE TABLE IF NOT EXISTS quizzes (
            id TEXT PRIMARY KEY,
            course_id TEXT,
            module_id TEXT,
            title TEXT NOT NULL,
            questions JSONB DEFAULT '[]'::jsonb,
            passing_score INTEGER DEFAULT 70,
            time_limit_minutes INTEGER DEFAULT 30,
            created_by TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """,
    "discussions": """
        CREATE TABLE IF NOT EXISTS discussions (
            id TEXT PRIMARY KEY,
            course_id TEXT,
            title TEXT NOT NULL,
            content TEXT NOT NULL,
            author_id TEXT,
            author_name TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """,
    "expert_questions": """
        CREATE TABLE IF NOT EXISTS expert_questions (
            id TEXT PRIMARY KEY,
            course_id TEXT,
            question TEXT NOT NULL,
            asked_by TEXT,
            asked_by_name TEXT,
            answer TEXT,
            answered_by TEXT,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """,
    "certificates": """
        CREATE TABLE IF NOT EXISTS certificates (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            course_id TEXT NOT NULL,
            issue_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            certificate_url TEXT
        )
    """
}

# ==================== HELPERS ====================
def generate_id():
    return str(int(time.time() * 1000))


# ==================== MODELS ====================
class UserCreate(BaseModel):
    email: str
    password: str
    name: str
    role: str = "student"
    interests: List[str] = []

class CourseCreate(BaseModel):
    title: str
    description: str
    category: str
    difficulty: str = "beginner"
    tags: List[str] = []
    thumbnail: Optional[str] = None
    is_published: bool = False

class ModuleContent(BaseModel):
    id: str = Field(default_factory=generate_id)
    title: str
    content_type: str
    content_url: Optional[str] = None
    content_text: Optional[str] = None
    duration_minutes: int = 10
    order: int = 0

class LearningPathCreate(BaseModel):
    title: str
    description: str
    course_ids: List[str]
    target_interests: List[str] = []

class ProgressUpdate(BaseModel):
    course_id: str
    module_id: str
    completed: bool
    time_spent: int = 0

class SessionCreate(BaseModel):
    course_id: str
    module_id: str
    name: str
    duration_minutes: int
    content_type: str
    content_text: Optional[str] = None
    quiz_id: Optional[str] = None

# ==================== AUTH HELPERS ====================
def get_password_hash(password): return pwd_context.hash(password)
def verify_password(p, h): return pwd_context.verify(p, h)

def create_access_token(data):
    data["exp"] = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db=Depends(get_db)
):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        uid = payload.get("sub")
        cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        cur.execute(TABLE_SCHEMAS["users"])
        cur.execute("SELECT * FROM users WHERE id=%s", (uid,))
        user = cur.fetchone()
        if not user:
            raise HTTPException(401, "User not found")
        return user
    except JWTError:
        raise HTTPException(401, "Invalid token")

def require_admin(user=Depends(get_current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "Admin only")
    return user

# ==================== NOTIFICATIONS ====================
def create_notification(uid, msg, ntype, db):
    cur = db.cursor()
    cur.execute(TABLE_SCHEMAS["notifications"])
    cur.execute("""
        INSERT INTO notifications
        (id, user_id, message, type, read, created_at)
        VALUES (%s,%s,%s,%s,%s,%s)
    """, (generate_id(), uid, msg, ntype, False, datetime.utcnow()))
    db.commit()

# ==================== AUTH ROUTES ====================
@api_router.post("/auth/register")
def register(user: UserCreate, db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["users"])
    cur.execute("SELECT 1 FROM users WHERE email=%s", (user.email.lower(),))
    if cur.fetchone():
        raise HTTPException(400, "Email exists")

    uid = generate_id()
    cur.execute("""
        INSERT INTO users
        (id,email,password_hash,name,role,profile,interests,created_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
        uid, user.email.lower(),
        # get_password_hash(user.password),
        user.password,
        user.name, user.role,
        psycopg2.extras.Json({"bio":"", "avatar":None}),
        psycopg2.extras.Json(user.interests),
        datetime.utcnow()
    ))
    db.commit()
    
    # Fetch the created user to return user data
    cur.execute("SELECT * FROM users WHERE id=%s", (uid,))
    new_user = cur.fetchone()
    user_data = dict(new_user)
    user_data.pop("password_hash", None)
    
    return {
        "access_token": create_access_token({"sub": uid}),
        "user": user_data
    }

@api_router.post("/auth/login")
def login(data: Dict[str,str], db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["users"])
    cur.execute("SELECT * FROM users WHERE email=%s", (data["email"].lower(),))
    user = cur.fetchone()
    if not user or not data["password"] == user["password_hash"]:
        raise HTTPException(401, "Invalid credentials")
    
    # Remove sensitive data from user object
    user_data = dict(user)
    user_data.pop("password_hash", None)
    
    return {
        "access_token": create_access_token({"sub": user["id"]}),
        "user": user_data
    }

@api_router.get("/auth/me")
def get_me(user=Depends(get_current_user)):
    user_data = dict(user)
    user_data.pop("password_hash", None)
    return user_data

class ProfileUpdate(BaseModel):
    interests: List[str]

@api_router.put("/auth/profile")
def update_profile(
    data: ProfileUpdate,
    name: Optional[str] = None,
    bio: Optional[str] = None,
    user=Depends(get_current_user),
    db=Depends(get_db)
):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["users"])
    profile = user["profile"] or {"bio": "", "avatar": None}
    if bio is not None:
        profile["bio"] = bio
    
    cur.execute("""
        UPDATE users SET 
        name=COALESCE(%s, name),
        profile=%s,
        interests=%s
        WHERE id=%s
    """, (name, psycopg2.extras.Json(profile), psycopg2.extras.Json(data.interests), user["id"]))
    db.commit()
    
    cur.execute("SELECT * FROM users WHERE id=%s", (user["id"],))
    updated_user = cur.fetchone()
    user_data = dict(updated_user)
    user_data.pop("password_hash", None)
    return user_data

# ==================== COURSES ====================
@api_router.post("/courses")
def create_course(course: CourseCreate, admin=Depends(require_admin), db=Depends(get_db)):
    cid = generate_id()
    cur = db.cursor()
    cur.execute(TABLE_SCHEMAS["courses"])
    cur.execute("""
        INSERT INTO courses VALUES
        (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
        cid, course.title, course.description, course.category,
        course.difficulty,
        psycopg2.extras.Json(course.tags),
        psycopg2.extras.Json([]),
        course.thumbnail, admin["id"],
        datetime.utcnow(), course.is_published
    ))
    db.commit()
    
    # Return the full course object
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM courses WHERE id=%s", (cid,))
    return cur.fetchone()

@api_router.get("/courses")
def get_courses(db=Depends(get_db), user=Depends(get_current_user)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["courses"])
    if user["role"] == "admin":
        cur.execute("SELECT * FROM courses")
    else:
        cur.execute("SELECT * FROM courses WHERE is_published=true")
    return cur.fetchall()

@api_router.get("/courses/{cid}")
def get_course(cid: str, db=Depends(get_db), user=Depends(get_current_user)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["courses"])
    cur.execute("SELECT * FROM courses WHERE id=%s", (cid,))
    course = cur.fetchone()
    if not course:
        raise HTTPException(404, "Course not found")
        
    # Fetch all sessions for this course to calculate module stats
    cur.execute("SELECT module_id, duration_minutes FROM sessions WHERE course_id=%s", (cid,))
    all_sessions = cur.fetchall()
    
    # Aggregate stats
    stats = {}
    for s in all_sessions:
        mid = s["module_id"]
        if mid not in stats:
            stats[mid] = {"session_count": 0, "total_duration": 0}
        stats[mid]["session_count"] += 1
        stats[mid]["total_duration"] += s["duration_minutes"]
        
    # Inject stats into modules
    modules = course.get("modules", []) or []
    for m in modules:
        m_stats = stats.get(m["id"], {"session_count": 0, "total_duration": 0})
        m["session_count"] = m_stats["session_count"]
        m["total_duration"] = m_stats["total_duration"]
    
    course["modules"] = modules
    return course

@api_router.put("/courses/{cid}")
def update_course(cid: str, course: CourseCreate, admin=Depends(require_admin), db=Depends(get_db)):
    cur = db.cursor()
    cur.execute(TABLE_SCHEMAS["courses"])
    cur.execute("""
        UPDATE courses SET title=%s, description=%s, category=%s, difficulty=%s, tags=%s, thumbnail=%s, is_published=%s
        WHERE id=%s
    """, (
        course.title, course.description, course.category, course.difficulty,
        psycopg2.extras.Json(course.tags), course.thumbnail, course.is_published, cid
    ))
    if cur.rowcount == 0:
        raise HTTPException(404, "Course not found")
    db.commit()
    
    # Return the full course object
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM courses WHERE id=%s", (cid,))
    return cur.fetchone()

@api_router.put("/courses/{cid}/publish")
def publish_course(cid: str, admin=Depends(require_admin), db=Depends(get_db)):
    cur = db.cursor()
    cur.execute(TABLE_SCHEMAS["courses"])
    cur.execute("UPDATE courses SET is_published=true WHERE id=%s", (cid,))
    if cur.rowcount == 0:
        raise HTTPException(404, "Not found")
    db.commit()
    return {"message":"Published"}

# ==================== MODULES ====================
@api_router.post("/courses/{cid}/modules")
def add_module(cid: str, module: ModuleContent, admin=Depends(require_admin), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["courses"])
    cur.execute("SELECT modules FROM courses WHERE id=%s", (cid,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(404, "Course not found")
    modules = row["modules"] or []
    module.order = len(modules)
    modules.append(module.dict())
    cur.execute("UPDATE courses SET modules=%s WHERE id=%s",
                (psycopg2.extras.Json(modules), cid))
    db.commit()
    return {"message":"Module added"}

@api_router.put("/courses/{cid}/modules/{mid}")
def update_module(cid: str, mid: str, module: ModuleContent, admin=Depends(require_admin), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["courses"])
    cur.execute("SELECT modules FROM courses WHERE id=%s", (cid,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(404, "Course not found")
    modules = row["modules"] or []
    found = False
    for i, m in enumerate(modules):
        if m["id"] == mid:
            modules[i] = {**module.dict(), "id": mid}
            found = True
            break
    if not found:
        raise HTTPException(404, "Module not found")
    cur.execute("UPDATE courses SET modules=%s WHERE id=%s",
                (psycopg2.extras.Json(modules), cid))
    db.commit()
    
    # Return full course
    cur.execute("SELECT * FROM courses WHERE id=%s", (cid,))
    return cur.fetchone()

@api_router.delete("/courses/{cid}/modules/{mid}")
def delete_module(cid: str, mid: str, admin=Depends(require_admin), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["courses"])
    cur.execute("SELECT modules FROM courses WHERE id=%s", (cid,))
    row = cur.fetchone()
    if not row:
        raise HTTPException(404, "Course not found")
    modules = row["modules"] or []
    modules = [m for m in modules if m["id"] != mid]
    cur.execute("UPDATE courses SET modules=%s WHERE id=%s",
                (psycopg2.extras.Json(modules), cid))
    db.commit()
    
    # Return full course
    cur.execute("SELECT * FROM courses WHERE id=%s", (cid,))
    return cur.fetchone()

# ==================== ADMIN ====================
@api_router.get("/admin/analytics")
def get_analytics(admin=Depends(require_admin), db=Depends(get_db)):
    cur = db.cursor()
    cur.execute(TABLE_SCHEMAS["users"])
    cur.execute("SELECT count(*) FROM users")
    user_count = cur.fetchone()[0]
    
    cur.execute(TABLE_SCHEMAS["courses"])
    cur.execute("SELECT count(*) FROM courses")
    course_count = cur.fetchone()[0]
    
    cur.execute(TABLE_SCHEMAS["quizzes"])
    cur.execute("SELECT count(*) FROM quizzes")
    quiz_count = cur.fetchone()[0]
        
    cur.execute(TABLE_SCHEMAS["certificates"])
    cur.execute("SELECT count(*) FROM certificates")
    cert_count = cur.fetchone()[0]
        
    return {
        "users": {"total": user_count},
        "courses": {"total": course_count},
        "quizzes": {"total": quiz_count},
        "certificates": cert_count
    }

@api_router.get("/admin/users")
def get_admin_users(admin=Depends(require_admin), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["users"])
    cur.execute("SELECT * FROM users ORDER BY created_at DESC")
    users = cur.fetchall()
    for u in users:
        u.pop("password_hash", None)
    return users

# ==================== LEARNING PATHS ====================
@api_router.get("/learning-paths")
def get_learning_paths(db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(TABLE_SCHEMAS["learning_paths"])
        cur.execute("SELECT * FROM learning_paths")
        return cur.fetchall()
    except:
        db.rollback()
        return []

@api_router.get("/learning-paths/recommended")
def get_recommended_paths(user=Depends(get_current_user), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(TABLE_SCHEMAS["learning_paths"])
        # Simple recommendation based on user interests
        interests = user.get("interests", [])
        if not interests:
            cur.execute("SELECT * FROM learning_paths LIMIT 5")
        else:
            cur.execute("SELECT * FROM learning_paths WHERE target_interests ?| %s", (interests,))
        return cur.fetchall()
    except:
        db.rollback()
        return []

@api_router.post("/learning-paths")
def create_learning_path(path: LearningPathCreate, admin=Depends(require_admin), db=Depends(get_db)):
    pid = generate_id()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["learning_paths"])
    cur.execute("""
        INSERT INTO learning_paths (id, title, description, course_ids, target_interests, created_by, created_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s)
        RETURNING *
    """, (
        pid, path.title, path.description, 
        psycopg2.extras.Json(path.course_ids), 
        psycopg2.extras.Json(path.target_interests),
        admin["id"], datetime.utcnow()
    ))
    db.commit()
    return cur.fetchone()

# ==================== PROGRESS ====================
@api_router.get("/progress")
def get_progress(user=Depends(get_current_user), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(TABLE_SCHEMAS["progress"])
        cur.execute("SELECT * FROM progress WHERE user_id=%s", (user["id"],))
        return cur.fetchall()
    except:
        db.rollback()
        return []

@api_router.post("/progress")
def update_progress(data: ProgressUpdate, user=Depends(get_current_user), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(TABLE_SCHEMAS["progress"])
        cur.execute("""
            INSERT INTO progress (id, user_id, course_id, module_id, completed, time_spent, completed_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            ON CONFLICT (user_id, module_id) DO UPDATE SET
            completed=EXCLUDED.completed,
            time_spent=progress.time_spent + EXCLUDED.time_spent,
            completed_at=CASE WHEN EXCLUDED.completed THEN EXCLUDED.completed_at ELSE progress.completed_at END
            RETURNING *
        """, (
            str(generate_id()), user["id"], data.course_id, data.module_id,
            data.completed, data.time_spent, datetime.utcnow() if data.completed else None
        ))
        db.commit()
        return cur.fetchone()
    except Exception as e:
        db.rollback()
        raise HTTPException(500, str(e))

@api_router.get("/progress/course/{cid}")
def get_course_progress(cid: str, user=Depends(get_current_user), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Get total sessions
        cur.execute(TABLE_SCHEMAS["sessions"])
        cur.execute("SELECT count(*) FROM sessions WHERE course_id=%s", (cid,))
        total_sessions = cur.fetchone()["count"]
        
        # Get completed sessions
        cur.execute(TABLE_SCHEMAS.get("session_progress", "CREATE TABLE IF NOT EXISTS session_progress (id TEXT PRIMARY KEY, user_id TEXT, session_id TEXT, course_id TEXT, module_id TEXT, completed BOOLEAN DEFAULT FALSE, time_spent_minutes INTEGER DEFAULT 0, completed_at TIMESTAMP, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id, session_id))"))
        cur.execute("SELECT count(DISTINCT session_id) FROM session_progress WHERE user_id=%s AND course_id=%s AND completed=true", (user["id"], cid))
        completed_sessions = cur.fetchone()["count"]
        
        pct = (completed_sessions / total_sessions * 100) if total_sessions > 0 else 0
        
        # Get module progress (legacy/granular)
        try:
            cur.execute(TABLE_SCHEMAS["progress"])
            cur.execute("SELECT * FROM progress WHERE user_id=%s AND course_id=%s", (user["id"], cid))
            module_progress = cur.fetchall()
        except:
            module_progress = []

        return {
            "total_sessions": total_sessions,
            "completed_sessions": completed_sessions,
            "progress_percentage": pct,
            "total_modules": 0, # Deprecated but kept for type safety if needed temporarily
            "completed_modules": 0, # Deprecated
            "module_progress": module_progress
        }
    except Exception as e:
        print(f"Error in course progress: {e}")
        db.rollback()
        return {
            "total_sessions": 0,
            "completed_sessions": 0,
            "progress_percentage": 0,
            "module_progress": []
        }

@api_router.get("/progress/dashboard")
def get_dashboard_stats(user=Depends(get_current_user), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        # Get all courses to calculate totals
        cur.execute(TABLE_SCHEMAS["courses"])
        cur.execute("SELECT id, title, thumbnail FROM courses")
        courses = cur.fetchall()
        course_map = {c["id"]: {**c, "total_sessions": 0, "completed_sessions": 0} for c in courses}
        
        # Get total sessions count per course
        cur.execute(TABLE_SCHEMAS["sessions"])
        cur.execute("SELECT course_id, count(*) as count FROM sessions GROUP BY course_id")
        session_counts = cur.fetchall()
        for sc in session_counts:
            if sc["course_id"] in course_map:
                course_map[sc["course_id"]]["total_sessions"] = sc["count"]
        
        # Get completed sessions for user
        cur.execute(TABLE_SCHEMAS.get("session_progress", "CREATE TABLE IF NOT EXISTS session_progress (id TEXT PRIMARY KEY, user_id TEXT, session_id TEXT, course_id TEXT, module_id TEXT, completed BOOLEAN DEFAULT FALSE, time_spent_minutes INTEGER DEFAULT 0, completed_at TIMESTAMP, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id, session_id))"))
        cur.execute("""
            SELECT course_id, count(DISTINCT session_id) as count 
            FROM session_progress 
            WHERE user_id=%s AND completed=true 
            GROUP BY course_id
        """, (user["id"],))
        completed_counts = cur.fetchall()
        for cc in completed_counts:
            if cc["course_id"] in course_map:
                course_map[cc["course_id"]]["completed_sessions"] = cc["count"]
        
        # Identify active courses (from both new session_progress and old module progress)
        active_course_ids = set()
        
        # 1. From session_progress
        cur.execute("SELECT DISTINCT course_id FROM session_progress WHERE user_id=%s", (user["id"],))
        for row in cur.fetchall():
            active_course_ids.add(row["course_id"])
            
        # 2. From old progress (modules)
        try:
            cur.execute(TABLE_SCHEMAS["progress"])
            cur.execute("SELECT DISTINCT course_id FROM progress WHERE user_id=%s", (user["id"],))
            for row in cur.fetchall():
                active_course_ids.add(row["course_id"])
        except:
            pass # Old table might not exist or verify failed, ignore
        
        # Calculate stats
        total_courses_enrolled = 0
        total_sessions_completed = 0
        course_stats = []
        
        for cid, data in course_map.items():
            # Include if it is an active course for the user
            if cid in active_course_ids:
                total_courses_enrolled += 1
                total_sessions_completed += data["completed_sessions"]
                
                total = data["total_sessions"]
                completed = data["completed_sessions"]
                pct = (completed / total * 100) if total > 0 else 0
                
                course_stats.append({
                    "course_id": cid,
                    "course_title": data["title"],
                    "total_sessions": total,
                    "completed_sessions": completed,
                    "progress_percentage": pct
                })
        
        # Get certificates count
        cur.execute(TABLE_SCHEMAS["certificates"])
        cur.execute("SELECT count(*) FROM certificates WHERE user_id=%s", (user["id"],))
        cert_count = cur.fetchone()[0]
        
        # Get total time spent
        cur.execute("SELECT sum(time_spent_minutes) FROM session_progress WHERE user_id=%s", (user["id"],))
        total_time = cur.fetchone()["sum"] or 0

        return {
            "total_courses_enrolled": total_courses_enrolled,
            "total_modules_completed": total_sessions_completed, # Keeping key for compatibility, but it is sessions
            "total_sessions_completed": total_sessions_completed,
            "total_time_spent_minutes": total_time,
            "certificates_earned": cert_count,
            "course_stats": course_stats
        }
    except Exception as e:
        print(f"Error in dashboard stats: {e}")
        db.rollback()
        return {
            "total_courses_enrolled": 0,
            "total_modules_completed": 0,
            "total_sessions_completed": 0,
            "total_time_spent_minutes": 0,
            "certificates_earned": 0,
            "course_stats": []
        }

# ==================== QUIZZES ====================
@api_router.get("/quizzes")
def get_quizzes(course_id: Optional[str] = None, db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(TABLE_SCHEMAS["quizzes"])
        if course_id:
            cur.execute("SELECT * FROM quizzes WHERE course_id=%s", (course_id,))
        else:
            cur.execute("SELECT * FROM quizzes")
        return cur.fetchall()
    except:
        db.rollback()
        return []

@api_router.get("/quizzes/{qid}")
def get_quiz(qid: str, db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["quizzes"])
    cur.execute("SELECT * FROM quizzes WHERE id=%s", (qid,))
    quiz = cur.fetchone()
    if not quiz:
        raise HTTPException(404, "Quiz not found")
    return quiz

@api_router.post("/quizzes")
def create_quiz(data: Dict[str, Any], admin=Depends(require_admin), db=Depends(get_db)):
    qid = generate_id()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["quizzes"])
    cur.execute("""
        INSERT INTO quizzes (id, course_id, module_id, title, questions, passing_score, time_limit_minutes, created_by, created_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        RETURNING *
    """, (
        qid, data.get("course_id"), data.get("module_id"), data.get("title"),
        psycopg2.extras.Json(data.get("questions", [])),
        data.get("passing_score", 70),
        data.get("time_limit_minutes", 30),
        admin["id"], datetime.utcnow()
    ))
    db.commit()
    return cur.fetchone()

@api_router.post("/quizzes/{qid}/submit")
def submit_quiz(qid: str, data: Dict[str, Any], user=Depends(get_current_user), db=Depends(get_db)):
    # Very simplified submission logic
    return {"score": 100, "passed": True}

# ==================== DISCUSSIONS ====================
@api_router.get("/discussions")
def get_discussions(course_id: Optional[str] = None, db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(TABLE_SCHEMAS["discussions"])
        if course_id:
            cur.execute("SELECT * FROM discussions WHERE course_id=%s ORDER BY created_at DESC", (course_id,))
        else:
            cur.execute("SELECT * FROM discussions ORDER BY created_at DESC")
        return cur.fetchall()
    except:
        db.rollback()
        return []

@api_router.post("/discussions")
def create_discussion(data: Dict[str, Any], user=Depends(get_current_user), db=Depends(get_db)):
    did = generate_id()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["discussions"])
    cur.execute("""
        INSERT INTO discussions (id, course_id, title, content, author_id, author_name, created_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s)
        RETURNING *
    """, (
        did, data.get("course_id"), data.get("title"), data.get("content"),
        user["id"], user["name"], datetime.utcnow()
    ))
    db.commit()
    return cur.fetchone()

# ==================== EXPERT Q&A ====================
@api_router.get("/expert-questions")
def get_expert_questions(course_id: Optional[str] = None, db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(TABLE_SCHEMAS["expert_questions"])
        if course_id:
            cur.execute("SELECT * FROM expert_questions WHERE course_id=%s ORDER BY created_at DESC", (course_id,))
        else:
            cur.execute("SELECT * FROM expert_questions ORDER BY created_at DESC")
        return cur.fetchall()
    except:
        db.rollback()
        return []

@api_router.post("/expert-questions")
def ask_question(data: Dict[str, Any], user=Depends(get_current_user), db=Depends(get_db)):
    qid = generate_id()
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["expert_questions"])
    cur.execute("""
        INSERT INTO expert_questions (id, course_id, question, asked_by, asked_by_name, status, created_at)
        VALUES (%s,%s,%s,%s,%s,%s,%s)
        RETURNING *
    """, (
        qid, data.get("course_id"), data.get("question"),
        user["id"], user["name"], "pending", datetime.utcnow()
    ))
    db.commit()
    return cur.fetchone()

# ==================== CERTIFICATES ====================
@api_router.get("/certificates")
def get_certificates(user=Depends(get_current_user), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(TABLE_SCHEMAS["certificates"])
        cur.execute("SELECT * FROM certificates WHERE user_id=%s", (user["id"],))
        return cur.fetchall()
    except:
        db.rollback()
        return []

# ==================== NOTIFICATIONS ====================
@api_router.get("/notifications")
def get_notifications(user=Depends(get_current_user), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    try:
        cur.execute(TABLE_SCHEMAS["notifications"])
        cur.execute("SELECT * FROM notifications WHERE user_id=%s ORDER BY created_at DESC", (user["id"],))
        return cur.fetchall()
    except:
        db.rollback()
        return []

@api_router.put("/notifications/{nid}/read")
def mark_notification_read(nid: str, user=Depends(get_current_user), db=Depends(get_db)):
    cur = db.cursor()
    cur.execute(TABLE_SCHEMAS["notifications"])
    cur.execute("UPDATE notifications SET read=true WHERE id=%s AND user_id=%s", (nid, user["id"]))
    db.commit()
    return {"status": "success"}

@api_router.put("/notifications/read-all")
def mark_all_notifications_read(user=Depends(get_current_user), db=Depends(get_db)):
    cur = db.cursor()
    cur.execute(TABLE_SCHEMAS["notifications"])
    cur.execute("UPDATE notifications SET read=true WHERE user_id=%s", (user["id"],))
    db.commit()
    return {"status": "success"}

# ==================== SESSIONS ====================
@api_router.post("/sessions")
async def create_session(
    course_id: str = Form(...),
    module_id: str = Form(...),
    name: str = Form(...),
    duration_minutes: str = Form(...),
    content_type: str = Form(...),
    content_text: Optional[str] = Form(None),
    quiz_id: Optional[str] = Form(None),
    content_url: Optional[str] = Form(None),
    is_document_available: str = Form("false"),
    admin=Depends(require_admin),
    db=Depends(get_db)
):
    sid = generate_id()
    
    try:
        duration = int(duration_minutes)
    except:
        duration = 0
    
    is_doc_bool = is_document_available.lower() == "true"

    
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["courses"])
    cur.execute(TABLE_SCHEMAS["sessions"])
    cur.execute("""
        INSERT INTO sessions 
        (id, course_id, module_id, name, duration_minutes, content_type, content_url, content_text, quiz_id, is_document_available)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        RETURNING *
    """, (sid, course_id, module_id, name, duration, content_type, content_url, content_text, quiz_id, is_doc_bool))
    
    session = cur.fetchone()
    db.commit()
    return session

@api_router.get("/courses/{cid}/modules/{mid}/sessions")
def get_sessions(cid: str, mid: str, user=Depends(get_current_user), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["sessions"])
    cur.execute("SELECT * FROM sessions WHERE course_id=%s AND module_id=%s ORDER BY created_at ASC", (cid, mid))
    sessions = cur.fetchall()
    
    # Get progress
    cur.execute(TABLE_SCHEMAS.get("session_progress", "CREATE TABLE IF NOT EXISTS session_progress (id TEXT PRIMARY KEY, user_id TEXT, session_id TEXT, course_id TEXT, module_id TEXT, completed BOOLEAN DEFAULT FALSE, time_spent_minutes INTEGER DEFAULT 0, completed_at TIMESTAMP, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id, session_id))"))
    cur.execute("SELECT session_id FROM session_progress WHERE user_id=%s AND course_id=%s AND module_id=%s AND completed=true", (user["id"], cid, mid))
    completed_ids = {row["session_id"] for row in cur.fetchall()}
    
    for s in sessions:
        s["completed"] = s["id"] in completed_ids
        
    return sessions

@api_router.get("/sessions/{sid}")
def get_session(sid: str, db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS["sessions"])
    cur.execute("SELECT * FROM sessions WHERE id=%s", (sid,))
    session = cur.fetchone()
    if not session:
        raise HTTPException(404, "Session not found")
    return session

@api_router.delete("/sessions/{sid}")
def delete_session(sid: str, admin=Depends(require_admin), db=Depends(get_db)):
    cur = db.cursor()
    cur.execute(TABLE_SCHEMAS["sessions"])
    cur.execute("DELETE FROM sessions WHERE id=%s", (sid,))
    if cur.rowcount == 0:
        raise HTTPException(404, "Session not found")
    db.commit()
    return {"message": "Session deleted"}

@api_router.post("/sessions/{sid}/complete")
def complete_session(sid: str, user=Depends(get_current_user), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS.get("session_progress", "CREATE TABLE IF NOT EXISTS session_progress (id TEXT PRIMARY KEY, user_id TEXT, session_id TEXT, course_id TEXT, module_id TEXT, completed BOOLEAN DEFAULT FALSE, time_spent_minutes INTEGER DEFAULT 0, completed_at TIMESTAMP, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id, session_id))"))
    
    # Get session details
    cur.execute(TABLE_SCHEMAS["sessions"])
    cur.execute("SELECT course_id, module_id FROM sessions WHERE id=%s", (sid,))
    session = cur.fetchone()
    if not session:
        raise HTTPException(404, "Session not found")
    
    # Check if already completed
    cur.execute("SELECT * FROM session_progress WHERE user_id=%s AND session_id=%s", (user["id"], sid))
    existing = cur.fetchone()
    
    if existing:
        # Update
        cur.execute("""
            UPDATE session_progress SET completed=true, completed_at=%s 
            WHERE user_id=%s AND session_id=%s
        """, (datetime.utcnow(), user["id"], sid))
    else:
        # Insert
        progress_id = generate_id()
        cur.execute("""
            INSERT INTO session_progress (id, user_id, session_id, course_id, module_id, completed, completed_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (progress_id, user["id"], sid, session["course_id"], session["module_id"], True, datetime.utcnow()))
    
    db.commit()
    return {"message": "Session completed", "session_id": sid}

@api_router.get("/sessions/{sid}/progress")
def get_session_progress(sid: str, user=Depends(get_current_user), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute(TABLE_SCHEMAS.get("session_progress", "CREATE TABLE IF NOT EXISTS session_progress (id TEXT PRIMARY KEY, user_id TEXT, session_id TEXT, course_id TEXT, module_id TEXT, completed BOOLEAN DEFAULT FALSE, time_spent_minutes INTEGER DEFAULT 0, completed_at TIMESTAMP, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id, session_id))"))
    cur.execute("SELECT * FROM session_progress WHERE user_id=%s AND session_id=%s", (user["id"], sid))
    progress = cur.fetchone()
    return progress or {"completed": False}



# ==================== CATEGORIES ====================
@api_router.get("/categories")
def get_categories():
    return [
        "Programming",
        "Data Science",
        "Web Development",
        "Mobile Development",
        "Design",
        "Business",
        "Marketing",
        "Finance",
    ]

# ==================== HEALTH ====================
@api_router.get("/health")
def health():
    return {"status":"ok","time":datetime.utcnow()}

# ==================== FINAL ====================
app.include_router(api_router) 
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=["*"],
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
