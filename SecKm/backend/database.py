from sqlalchemy import create_engine, text
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker

# 使用本地 SQLite 数据库，方便测试
SQLALCHEMY_DATABASE_URL = "sqlite:///./security_alerts.db"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

def init_db():
    with engine.begin() as conn:
        columns = {row[1] for row in conn.execute(text("PRAGMA table_info(alert_records)"))}
        
        # 动态补全缺少的字段，防止批量研判报错
        if "threat_level" not in columns:
            conn.execute(text("ALTER TABLE alert_records ADD COLUMN threat_level VARCHAR"))
        if "created_at" not in columns:
            conn.execute(text("ALTER TABLE alert_records ADD COLUMN created_at DATETIME"))
        if "status" not in columns:
            conn.execute(text("ALTER TABLE alert_records ADD COLUMN status VARCHAR DEFAULT 'pending'"))
        if "initial_observation" not in columns:
            conn.execute(text("ALTER TABLE alert_records ADD COLUMN initial_observation TEXT"))
        if "deep_analysis" not in columns:
            conn.execute(text("ALTER TABLE alert_records ADD COLUMN deep_analysis TEXT"))
        if "final_conclusion" not in columns:
            conn.execute(text("ALTER TABLE alert_records ADD COLUMN final_conclusion TEXT"))
        if "suggestions" not in columns:
            conn.execute(text("ALTER TABLE alert_records ADD COLUMN suggestions TEXT"))

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()