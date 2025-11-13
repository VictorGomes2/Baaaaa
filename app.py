# app.py
# =============================================================================
# FastAPI + SQLAlchemy + JWT - VERSÃO FINAL COM CORREÇÃO DE DRIVER ASYNC
# =============================================================================

import os
import sys
import re
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse

from sqlalchemy import String, Integer, DateTime, func, select, Text, ForeignKey, Boolean
from sqlalchemy.orm import Mapped, mapped_column, declarative_base, relationship
from sqlalchemy.ext.asyncio import (
    create_async_engine,
    async_sessionmaker,
    AsyncSession,
)

from passlib.context import CryptContext
from jose import jwt, JWTError

# =============================================================================
# Configurações de Ambiente
# =============================================================================

# Configuração do Banco de Dados
DATABASE_URL_RAW = os.getenv("DATABASE_URL", "").strip()

# Se não estiver em ambiente Render/produção, usa SQLite local como fallback
if not DATABASE_URL_RAW:
    DATABASE_URL_RAW = "sqlite+aiosqlite:///./terrasrf.db" 

connect_args = {}

# +++ CORREÇÃO DE DEPLOY: Forçar driver assíncrono para PostgreSQL (Render) +++
# O Render fornece DATABASE_URL como 'postgresql://...', mas o SQLAlchemy Async
# precisa de 'postgresql+asyncpg://...' para usar o asyncpg.
if DATABASE_URL_RAW.startswith("postgresql://"):
    DATABASE_URL = DATABASE_URL_RAW.replace("postgresql://", "postgresql+asyncpg://", 1)
else:
    DATABASE_URL = DATABASE_URL_RAW
    # Mantém o tratamento para SQLite
    if DATABASE_URL_RAW.startswith("sqlite"):
        connect_args = {"check_same_thread": False}
# +++ FIM DA CORREÇÃO +++

if not DATABASE_URL:
    raise RuntimeError("A variável de ambiente DATABASE_URL não foi definida.")

# Configuração JWT
JWT_SECRET = os.getenv("JWT_SECRET", "super-secret-key-change-me")
JWT_ALG = "HS256"
JWT_EXPIRES_MIN = int(os.getenv("JWT_EXPIRES_MIN", "360"))

# Configuração de Usuário Admin Inicial
INIT_ADMIN = os.getenv("INIT_ADMIN", "admin")
INIT_PASS = os.getenv("INIT_PASS", "admin123")


# =============================================================================
# Configurações de Banco de Dados e SQLAlchemy
# =============================================================================

engine = create_async_engine(
    DATABASE_URL, 
    echo=False, 
    connect_args=connect_args
)
AsyncSessionLocal = async_sessionmaker(
    autocommit=False, 
    autoflush=False, 
    bind=engine
)

Base = declarative_base()

# Contexto de Hash de Senhas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Função para obter a sessão do banco de dados
async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

# Função para criar todas as tabelas (chamada ao iniciar o app)
async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    
    # Cria o usuário admin inicial
    async with AsyncSessionLocal() as session:
        try:
            res = await session.execute(select(User).where(User.username == INIT_ADMIN))
            if not res.scalar_one_or_none():
                hashed_password = pwd_context.hash(INIT_PASS)
                admin_user = User(
                    username=INIT_ADMIN,
                    hashed_password=hashed_password,
                    is_active=True,
                    is_admin=True
                )
                session.add(admin_user)
                await session.commit()
                print(f"Usuário admin inicial '{INIT_ADMIN}' criado com sucesso.")
        except Exception as e:
            # Em produção, pode ser um erro de permissão ou conexão; melhor registrar.
            print(f"Erro ao inicializar o usuário admin: {e}")


# =============================================================================
# Modelos SQLAlchemy (DB Models)
# =============================================================================

class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(100))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_admin: Mapped[bool] = mapped_column(Boolean, default=False)
    
    layers: Mapped[List["Layer"]] = relationship(back_populates="owner", cascade="all, delete-orphan")

class Layer(Base):
    __tablename__ = "layers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    type: Mapped[str] = mapped_column(String(50))  # Ex: 'Point', 'LineString', 'Polygon'
    group_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True) # Para agrupamento no frontend
    geojson_data: Mapped[Optional[str]] = mapped_column(Text)
    
    # CORREÇÃO #1: Campo para armazenar a configuracao de labels/simbologia
    style_config: Mapped[Optional[str]] = mapped_column(Text, nullable=True) 
    
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now())
    
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    owner: Mapped["User"] = relationship(back_populates="layers")


# =============================================================================
# Schemas Pydantic (Request/Response Models)
# =============================================================================

class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    id: int
    is_active: bool
    is_admin: bool
    
    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class LayerBase(BaseModel):
    name: str
    type: str
    group_name: Optional[str] = None
    geojson_data: Optional[str] = None
    
    # CORREÇÃO #2: Novo campo para Pydantic Base e Update
    style_config: Optional[str] = None 
    
class LayerCreate(LayerBase):
    pass

class LayerUpdate(LayerBase):
    pass

class LayerResponse(LayerBase):
    id: int
    owner_id: int
    created_at: datetime
    updated_at: datetime
    
    # CORREÇÃO #3: Novo campo para Pydantic Response
    style_config: Optional[str] = None 
    
    class Config:
        from_attributes = True


# =============================================================================
# Segurança e Autenticação (JWT)
# =============================================================================

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=JWT_EXPIRES_MIN)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALG)
    return encoded_jwt

def get_password_hash(password):
    return pwd_context.hash(password)

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

async def authenticate_user(db: AsyncSession, username: str, password: str):
    res = await db.execute(select(User).where(User.username == username))
    user = res.scalar_one_or_none()
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

async def get_current_user(request: Request, db: AsyncSession = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Credenciais inválidas ou token expirado",
        headers={"WWW-Authenticate": "Bearer"},
    )
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    
    if not token:
        raise credentials_exception
        
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
        
    res = await db.execute(select(User).where(User.username == token_data.username))
    user = res.scalar_one_or_none()
    
    if user is None:
        raise credentials_exception
    return user


# =============================================================================
# Configuração do FastAPI e Middlewares
# =============================================================================

app = FastAPI(
    title="Terra SRF Backend - API de Sincronização GIS",
    on_startup=[init_db]
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Ajuste para domínios específicos em produção
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# =============================================================================
# Endpoints de Autenticação
# =============================================================================

@app.post("/token", response_model=Token, tags=["Autenticação"])
async def login_for_access_token(
    request: Request, db: AsyncSession = Depends(get_db)
):
    """
    Endpoint de login. Recebe 'username' e 'password' no corpo da requisição (form-data).
    """
    try:
        form = await request.form()
        username = form.get("username")
        password = form.get("password")
        
        if not username or not password:
             raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Campos 'username' e 'password' são obrigatórios."
            )

    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Requisição inválida (esperado form-data)."
        )

    user = await authenticate_user(db, username, password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nome de usuário ou senha incorretos",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=JWT_EXPIRES_MIN)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}


# =============================================================================
# Endpoints de Camadas (CRUD)
# =============================================================================

@app.get("/api/layers", response_model=List[LayerResponse], tags=["Camadas"])
async def get_layers(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retorna todas as camadas do usuário logado.
    """
    res = await db.execute(select(Layer).where(Layer.owner_id == current_user.id).order_by(Layer.id))
    layers = res.scalars().all()
    return layers

@app.post("/api/layers", response_model=LayerResponse, status_code=status.HTTP_201_CREATED, tags=["Camadas"])
async def create_layer(
    layer_create: LayerCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Cria uma nova camada para o usuário logado.
    """
    db_layer = Layer(
        name=layer_create.name,
        type=layer_create.type,
        group_name=layer_create.group_name,
        geojson_data=layer_create.geojson_data,
        owner_id=current_user.id,
        
        # CORREÇÃO #4: Salvamento do novo campo na criação
        style_config=layer_create.style_config 
    )
    db.add(db_layer)
    await db.commit()
    await db.refresh(db_layer)
    return db_layer

@app.put("/api/layers/{layer_id}", response_model=LayerResponse, tags=["Camadas"])
async def update_layer(
    layer_id: int,
    layer_update: LayerUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Atualiza os dados de uma camada existente do usuário logado.
    """
    res = await db.execute(select(Layer).where(Layer.id == layer_id))
    db_layer = res.scalar_one_or_none()

    if not db_layer or db_layer.owner_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Camada não encontrada ou você não é o proprietário desta camada.")

    # Atualiza os dados
    db_layer.name = layer_update.name
    db_layer.type = layer_update.type
    db_layer.geojson_data = layer_update.geojson_data
    db_layer.group_name = layer_update.group_name
    
    # CORREÇÃO #5: Salvamento do novo campo na atualização
    db_layer.style_config = layer_update.style_config 

    await db.commit()
    await db.refresh(db_layer)
    return db_layer

@app.delete("/api/layers/{layer_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Camadas"])
async def delete_layer(
    layer_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Deleta uma camada do usuário logado.
    """
    res = await db.execute(select(Layer).where(Layer.id == layer_id))
    db_layer = res.scalar_one_or_none()

    if db_layer and db_layer.owner_id == current_user.id:
        await db.delete(db_layer)
        await db.commit()
    
    return


# =============================================================================
# Endpoint de Status
# =============================================================================

@app.get("/", tags=["Status"])
async def root():
    return {"message": "API de Sincronização GIS (Terra SRF) está operacional."}