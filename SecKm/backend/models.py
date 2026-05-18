from sqlalchemy import Column, Integer, String, Text, DateTime
from database import Base
import datetime

class AlertRecord(Base):
    __tablename__ = "alert_records"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String, index=True)
    dest_ip = Column(String)
    dest_port = Column(String)
    protocol = Column(String)
    req_header = Column(Text)
    req_body = Column(Text)
    res_header = Column(Text)
    res_body = Column(Text)
    
    # AI 研判结果
    ai_raw_response = Column(Text)       # 大模型返回的完整文本
    ai_attack_type = Column(String)      # AI 判断的类型
    threat_level = Column(String)        # 威胁等级
    
    # 大模型分段结论
    initial_observation = Column(Text)
    deep_analysis = Column(Text)
    final_conclusion = Column(Text)
    suggestions = Column(Text)
    
    # 时间与状态
    created_at = Column(DateTime, default=datetime.datetime.now)
    human_verified_type = Column(String) # 人工确认/纠错的真实类型
    status = Column(String, default="pending") # pending(待研判), analyzed(已研判), failed(失败)