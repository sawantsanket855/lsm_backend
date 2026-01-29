from fastapi import FastAPI, APIRouter, HTTPException, Depends
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
import psycopg2
import psycopg2.extras
import os
import uuid
from datetime import datetime
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional

# ==================== Setup ====================

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

def get_db():
    conn = psycopg2.connect(
        host=os.getenv("POSTGRES_HOST"),
        port=os.getenv("POSTGRES_PORT"),
        database=os.getenv("POSTGRES_DB"),
        user=os.getenv("POSTGRES_USER"),
        password=os.getenv("POSTGRES_PASSWORD"),
        cursor_factory=psycopg2.extras.RealDictCursor
    )
    try:
        yield conn
    finally:
        conn.close()

app = FastAPI()
api_router = APIRouter(prefix="/api")

# ==================== Models ====================

class StudentCreate(BaseModel):
    first_name: str
    last_name: str
    email: str
    phone: str

class Student(StudentCreate):
    id: str
    created_at: datetime
    updated_at: datetime

class StudentLogin(BaseModel):
    email: str

class CustomValueCreate(BaseModel):
    name: str
    description: str
    category: str
    user_id: str

class CustomValue(CustomValueCreate):
    id: str
    created_at: datetime

class Answer(BaseModel):
    question_id: str
    selected_option: int

class RankedValue(BaseModel):
    value_id: str
    rank: int

class AssessmentCreate(BaseModel):
    user_id: str
    template_type: str
    answers: List[Answer]
    discovered_values: List[str]
    ranked_values: List[RankedValue]
    custom_values: List[str] = []

class Assessment(AssessmentCreate):
    id: str
    date_taken: datetime

class GoalCreate(BaseModel):
    user_id: str
    title: str
    description: str
    related_values: List[str]

class GoalUpdate(BaseModel):
    title: Optional[str]
    description: Optional[str]
    related_values: Optional[List[str]]
    status: Optional[str]
    progress: Optional[int]

class Goal(GoalCreate):
    id: str
    status: str
    progress: int
    created_at: datetime
    updated_at: datetime

# ==================== Student Routes ====================

@api_router.post("/students/register", response_model=Student)
def register_student(student: StudentCreate, db=Depends(get_db)):
    cur = db.cursor()
    cur.execute("SELECT 1 FROM students WHERE email=%s", (student.email.lower(),))
    if cur.fetchone():
        raise HTTPException(status_code=400, detail="Email already registered")

    now = datetime.utcnow()
    student_id = str(uuid.uuid4())

    cur.execute(
        """INSERT INTO students VALUES (%s,%s,%s,%s,%s,%s,%s)""",
        (student_id, student.first_name, student.last_name,
         student.email.lower(), student.phone, now, now)
    )
    db.commit()

    return {**student.dict(), "id": student_id, "created_at": now, "updated_at": now}

@api_router.post("/students/login", response_model=Student)
def login_student(login: StudentLogin, db=Depends(get_db)):
    cur = db.cursor()
    cur.execute("SELECT * FROM students WHERE email=%s", (login.email.lower(),))
    student = cur.fetchone()
    if not student:
        raise HTTPException(status_code=404, detail="Student not found")
    return student

# ==================== Custom Values ====================

@api_router.post("/custom-values", response_model=CustomValue)
def create_custom_value(value: CustomValueCreate, db=Depends(get_db)):
    cur = db.cursor()
    value_id = str(uuid.uuid4())
    now = datetime.utcnow()

    cur.execute(
        """INSERT INTO custom_values VALUES (%s,%s,%s,%s,%s,%s)""",
        (value_id, value.name, value.description,
         value.category, value.user_id, now)
    )
    db.commit()

    return {**value.dict(), "id": value_id, "created_at": now}

@api_router.get("/custom-values/{user_id}", response_model=List[CustomValue])
def get_custom_values(user_id: str, db=Depends(get_db)):
    cur = db.cursor()
    cur.execute("SELECT * FROM custom_values WHERE user_id=%s", (user_id,))
    return cur.fetchall()

# ==================== Assessments ====================

@api_router.post("/assessments", response_model=Assessment)
def create_assessment(data: AssessmentCreate, db=Depends(get_db)):
    cur = db.cursor()
    assessment_id = str(uuid.uuid4())
    now = datetime.utcnow()

    cur.execute(
        """INSERT INTO assessments VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
        (assessment_id, data.user_id, data.template_type,
         psycopg2.extras.Json([a.dict() for a in data.answers]),
         psycopg2.extras.Json(data.discovered_values),
         psycopg2.extras.Json([r.dict() for r in data.ranked_values]),
         psycopg2.extras.Json(data.custom_values),
         now)
    )
    db.commit()

    return {**data.dict(), "id": assessment_id, "date_taken": now}

@api_router.get("/assessments/{user_id}", response_model=List[Assessment])
def get_assessments(user_id: str, db=Depends(get_db)):
    cur = db.cursor()
    cur.execute("SELECT * FROM assessments WHERE user_id=%s", (user_id,))
    return cur.fetchall()

@api_router.get("/assessments/detail/{assessment_id}", response_model=Assessment)
def get_assessment_detail(assessment_id: str, db=Depends(get_db)):
    cur = db.cursor()
    cur.execute("SELECT * FROM assessments WHERE id=%s", (assessment_id,))
    assessment = cur.fetchone()
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found")
    return assessment

# ==================== Goals ====================

@api_router.post("/goals", response_model=Goal)
def create_goal(goal: GoalCreate, db=Depends(get_db)):
    cur = db.cursor()
    goal_id = str(uuid.uuid4())
    now = datetime.utcnow()

    cur.execute(
        """INSERT INTO goals VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
        (goal_id, goal.user_id, goal.title, goal.description,
         psycopg2.extras.Json(goal.related_values),
         "active", 0, now, now)
    )
    db.commit()

    return {**goal.dict(), "id": goal_id, "status": "active",
            "progress": 0, "created_at": now, "updated_at": now}

@api_router.get("/goals/{user_id}", response_model=List[Goal])
def get_goals(user_id: str, db=Depends(get_db)):
    cur = db.cursor()
    cur.execute("SELECT * FROM goals WHERE user_id=%s", (user_id,))
    return cur.fetchall()

@api_router.put("/goals/{goal_id}", response_model=Goal)
def update_goal(goal_id: str, update: GoalUpdate, db=Depends(get_db)):
    fields = {k: v for k, v in update.dict().items() if v is not None}
    if not fields:
        raise HTTPException(status_code=400, detail="No fields to update")

    fields["updated_at"] = datetime.utcnow()
    set_clause = ", ".join(f"{k}=%s" for k in fields)
    values = list(fields.values()) + [goal_id]

    cur = db.cursor()
    cur.execute(f"UPDATE goals SET {set_clause} WHERE id=%s", values)
    db.commit()

    cur.execute("SELECT * FROM goals WHERE id=%s", (goal_id,))
    goal = cur.fetchone()
    if not goal:
        raise HTTPException(status_code=404, detail="Goal not found")
    return goal

# ==================== Health ====================

@api_router.get("/health")
def health_check(db=Depends(get_db)):
    cur = db.cursor()
    cur.execute("SELECT 1")
    return {"status": "healthy", "database": "connected"}

# ==================== App Config ====================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)
