from fastapi import FastAPI, APIRouter, HTTPException, Depends, UploadFile, File
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import FileResponse
from starlette.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from pathlib import Path
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from psycopg2.pool import SimpleConnectionPool
import psycopg2, psycopg2.extras
import os, uuid, aiofiles
from datetime import datetime, timedelta
from passlib.context import CryptContext
from jose import jwt, JWTError

# ==================== ENV & APP ====================
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

UPLOAD_DIR = ROOT_DIR / "uploads"
UPLOAD_DIR.mkdir(exist_ok=True)

SECRET_KEY = os.getenv("JWT_SECRET")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7

app = FastAPI(title="LMS API", version="1.0.0")
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

class ModuleContent(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    title: str
    content_type: str
    content_url: Optional[str] = None
    content_text: Optional[str] = None
    duration_minutes: int = 10
    order: int = 0

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
    cur.execute("""
        INSERT INTO notifications
        VALUES (%s,%s,%s,%s,%s,%s)
    """, (str(uuid.uuid4()), uid, msg, ntype, False, datetime.utcnow()))
    db.commit()

# ==================== AUTH ROUTES ====================
@api_router.post("/auth/register")
def register(user: UserCreate, db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT 1 FROM users WHERE email=%s", (user.email.lower(),))
    if cur.fetchone():
        raise HTTPException(400, "Email exists")

    uid = str(uuid.uuid4())
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

# ==================== COURSES ====================
@api_router.post("/courses")
def create_course(course: CourseCreate, admin=Depends(require_admin), db=Depends(get_db)):
    cid = str(uuid.uuid4())
    cur = db.cursor()
    cur.execute("""
        INSERT INTO courses VALUES
        (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
        cid, course.title, course.description, course.category,
        course.difficulty,
        psycopg2.extras.Json(course.tags),
        psycopg2.extras.Json([]),
        course.thumbnail, admin["id"],
        datetime.utcnow(), False
    ))
    db.commit()
    return {"id": cid, **course.dict()}

@api_router.get("/courses")
def get_courses(db=Depends(get_db), user=Depends(get_current_user)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    if user["role"] == "admin":
        cur.execute("SELECT * FROM courses")
    else:
        cur.execute("SELECT * FROM courses WHERE is_published=true")
    return cur.fetchall()

@api_router.get("/courses/{cid}")
def get_course(cid: str, db=Depends(get_db), user=Depends(get_current_user)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    cur.execute("SELECT * FROM courses WHERE id=%s", (cid,))
    course = cur.fetchone()
    if not course:
        raise HTTPException(404, "Course not found")
    # if course["is_published"] == False and user["role"] != "admin":
    #     raise HTTPException(403, "Course not accessible")
    return course

@api_router.put("/courses/{cid}")
def update_course(cid: str, course: CourseCreate, admin=Depends(require_admin), db=Depends(get_db)):
    cur = db.cursor()
    cur.execute("""
        UPDATE courses SET title=%s, description=%s, category=%s, difficulty=%s, tags=%s, thumbnail=%s
        WHERE id=%s
    """, (
        course.title, course.description, course.category, course.difficulty,
        psycopg2.extras.Json(course.tags), course.thumbnail, cid
    ))
    if cur.rowcount == 0:
        raise HTTPException(404, "Course not found")
    db.commit()
    return course

@api_router.put("/courses/{cid}/publish")
def publish_course(cid: str, admin=Depends(require_admin), db=Depends(get_db)):
    cur = db.cursor()
    cur.execute("UPDATE courses SET is_published=true WHERE id=%s", (cid,))
    if cur.rowcount == 0:
        raise HTTPException(404, "Not found")
    db.commit()
    return {"message":"Published"}

# ==================== MODULES ====================
@api_router.post("/courses/{cid}/modules")
def add_module(cid: str, module: ModuleContent, admin=Depends(require_admin), db=Depends(get_db)):
    cur = db.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
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

# ==================== FILE UPLOAD ====================
@api_router.post("/upload")
async def upload(file: UploadFile = File(...), admin=Depends(require_admin)):
    fid = f"{uuid.uuid4()}_{file.filename}"
    path = UPLOAD_DIR / fid
    async with aiofiles.open(path, "wb") as f:
        await f.write(await file.read())
    return {"file_url": f"/api/files/{fid}"}

@api_router.get("/files/{fname}")
def get_file(fname: str):
    path = UPLOAD_DIR / fname
    if not path.exists():
        raise HTTPException(404, "File not found")
    return FileResponse(path)

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
