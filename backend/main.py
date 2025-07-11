import os
import asyncio
from datetime import datetime, timedelta
from typing import Optional, List
from pathlib import Path

from fastapi import FastAPI, HTTPException, Depends, status, WebSocket, WebSocketDisconnect, UploadFile, File
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import JWTError, jwt
import aiofiles
import json
import subprocess
import git
from pygments import highlight
from pygments.lexers import get_lexer_by_name, guess_lexer_for_filename
from pygments.formatters import JSONFormatter
import redis
import asyncio
from concurrent.futures import ThreadPoolExecutor

app = FastAPI(title="Advanced IDE", version="1.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
SECRET_KEY = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# Redis for real-time features
redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)

# Thread pool for blocking operations
executor = ThreadPoolExecutor(max_workers=4)

# Models
class User(BaseModel):
    username: str
    email: str
    hashed_password: str

class UserRegister(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class FileItem(BaseModel):
    name: str
    path: str
    type: str  # 'file' or 'directory'
    size: Optional[int] = None
    modified: Optional[datetime] = None

class FileContent(BaseModel):
    content: str
    language: Optional[str] = None

class GitStatus(BaseModel):
    branch: str
    staged: List[str]
    unstaged: List[str]
    untracked: List[str]

# In-memory user storage (replace with real database in production)
users_db = {}

# WebSocket connections
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def send_personal_message(self, message: str, websocket: WebSocket):
        await websocket.send_text(message)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            try:
                await connection.send_text(message)
            except:
                self.disconnect(connection)

manager = ConnectionManager()

# Auth utilities
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = users_db.get(username)
    if user is None:
        raise credentials_exception
    return user

# Auth endpoints
@app.post("/api/auth/register", response_model=Token)
async def register(user: UserRegister):
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="Username already registered")
    
    hashed_password = get_password_hash(user.password)
    users_db[user.username] = User(
        username=user.username,
        email=user.email,
        hashed_password=hashed_password
    )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/auth/login", response_model=Token)
async def login(user: UserLogin):
    db_user = users_db.get(user.username)
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/api/auth/me")
async def read_users_me(current_user: User = Depends(get_current_user)):
    return {"username": current_user.username, "email": current_user.email}

# File system endpoints
@app.get("/api/files", response_model=List[FileItem])
async def list_files(path: str = ".", current_user: User = Depends(get_current_user)):
    try:
        target_path = Path(path)
        if not target_path.exists():
            raise HTTPException(status_code=404, detail="Path not found")
        
        items = []
        for item in target_path.iterdir():
            if item.name.startswith('.'):
                continue
                
            stat = item.stat()
            items.append(FileItem(
                name=item.name,
                path=str(item),
                type="directory" if item.is_dir() else "file",
                size=stat.st_size if item.is_file() else None,
                modified=datetime.fromtimestamp(stat.st_mtime)
            ))
        
        return sorted(items, key=lambda x: (x.type != "directory", x.name.lower()))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/files/content")
async def get_file_content(path: str, current_user: User = Depends(get_current_user)):
    try:
        file_path = Path(path)
        if not file_path.exists() or not file_path.is_file():
            raise HTTPException(status_code=404, detail="File not found")
        
        async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
            content = await f.read()
        
        # Detect language
        try:
            lexer = guess_lexer_for_filename(file_path.name, content)
            language = lexer.name.lower()
        except:
            language = "text"
        
        return FileContent(content=content, language=language)
    except UnicodeDecodeError:
        raise HTTPException(status_code=400, detail="File is not text-readable")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/files/save")
async def save_file(path: str, content: str, current_user: User = Depends(get_current_user)):
    try:
        file_path = Path(path)
        file_path.parent.mkdir(parents=True, exist_ok=True)
        
        async with aiofiles.open(file_path, 'w', encoding='utf-8') as f:
            await f.write(content)
        
        # Broadcast file change to all connected clients
        await manager.broadcast(json.dumps({
            "type": "file_changed",
            "path": path,
            "user": current_user.username
        }))
        
        return {"message": "File saved successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/files/create")
async def create_file(path: str, is_directory: bool = False, current_user: User = Depends(get_current_user)):
    try:
        target_path = Path(path)
        if target_path.exists():
            raise HTTPException(status_code=400, detail="Path already exists")
        
        if is_directory:
            target_path.mkdir(parents=True)
        else:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.touch()
        
        return {"message": f"{'Directory' if is_directory else 'File'} created successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/files/delete")
async def delete_file(path: str, current_user: User = Depends(get_current_user)):
    try:
        target_path = Path(path)
        if not target_path.exists():
            raise HTTPException(status_code=404, detail="Path not found")
        
        if target_path.is_dir():
            import shutil
            shutil.rmtree(target_path)
        else:
            target_path.unlink()
        
        return {"message": "Deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Terminal endpoint
@app.websocket("/api/terminal")
async def terminal_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        # Start a shell process
        process = await asyncio.create_subprocess_shell(
            "/bin/bash",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT
        )
        
        async def read_output():
            while True:
                data = await process.stdout.read(1024)
                if not data:
                    break
                await websocket.send_text(data.decode('utf-8', errors='ignore'))
        
        # Start reading output
        output_task = asyncio.create_task(read_output())
        
        while True:
            data = await websocket.receive_text()
            if process.stdin:
                process.stdin.write(data.encode())
                await process.stdin.drain()
                
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        if process:
            process.terminate()
            await process.wait()

# Git endpoints
@app.get("/api/git/status", response_model=GitStatus)
async def git_status(current_user: User = Depends(get_current_user)):
    try:
        repo = git.Repo(".")
        
        # Get current branch
        branch = repo.active_branch.name
        
        # Get file statuses
        staged = [item.a_path for item in repo.index.diff("HEAD")]
        unstaged = [item.a_path for item in repo.index.diff(None)]
        untracked = repo.untracked_files
        
        return GitStatus(
            branch=branch,
            staged=staged,
            unstaged=unstaged,
            untracked=untracked
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/git/add")
async def git_add(files: List[str], current_user: User = Depends(get_current_user)):
    try:
        repo = git.Repo(".")
        repo.index.add(files)
        return {"message": "Files added to staging"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/git/commit")
async def git_commit(message: str, current_user: User = Depends(get_current_user)):
    try:
        repo = git.Repo(".")
        commit = repo.index.commit(message)
        return {"message": f"Committed: {commit.hexsha[:7]}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# Code analysis endpoints
@app.post("/api/code/format")
async def format_code(content: str, language: str, current_user: User = Depends(get_current_user)):
    try:
        if language.lower() == "python":
            # Format Python code with black
            process = await asyncio.create_subprocess_exec(
                "black", "--code", content,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            if process.returncode == 0:
                return {"formatted_content": stdout.decode()}
            else:
                raise HTTPException(status_code=400, detail=stderr.decode())
        else:
            return {"formatted_content": content}  # Return as-is for unsupported languages
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/code/lint")
async def lint_code(content: str, language: str, current_user: User = Depends(get_current_user)):
    try:
        if language.lower() == "python":
            # Use mypy for linting
            process = await asyncio.create_subprocess_exec(
                "mypy", "--show-error-codes", "-",
                input=content.encode(),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            return {"lint_output": stdout.decode() + stderr.decode()}
        else:
            return {"lint_output": "Linting not supported for this language"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# AI Chat endpoint (placeholder for AI integration)
@app.post("/api/ai/chat")
async def ai_chat(message: str, current_user: User = Depends(get_current_user)):
    # This is a placeholder - integrate with your preferred AI service
    return {
        "response": f"AI Assistant: I received your message '{message}'. This is a placeholder response. Integrate with OpenAI, Claude, or your preferred AI service here."
    }

# Search endpoints
@app.get("/api/search/files")
async def search_files(query: str, current_user: User = Depends(get_current_user)):
    try:
        results = []
        for root, dirs, files in os.walk("."):
            # Skip hidden directories
            dirs[:] = [d for d in dirs if not d.startswith('.')]
            
            for file in files:
                if not file.startswith('.') and query.lower() in file.lower():
                    file_path = os.path.join(root, file)
                    results.append({
                        "path": file_path,
                        "name": file,
                        "type": "file"
                    })
        
        return {"results": results[:50]}  # Limit results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/search/content")
async def search_content(query: str, current_user: User = Depends(get_current_user)):
    try:
        # Use grep for content search
        process = await asyncio.create_subprocess_exec(
            "grep", "-r", "-n", "--include=*.py", "--include=*.js", "--include=*.ts", 
            "--include=*.tsx", "--include=*.jsx", "--include=*.html", "--include=*.css",
            query, ".",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        
        results = []
        if stdout:
            lines = stdout.decode().split('\n')
            for line in lines[:50]:  # Limit results
                if ':' in line:
                    parts = line.split(':', 2)
                    if len(parts) >= 3:
                        results.append({
                            "file": parts[0],
                            "line": int(parts[1]) if parts[1].isdigit() else 0,
                            "content": parts[2]
                        })
        
        return {"results": results}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)