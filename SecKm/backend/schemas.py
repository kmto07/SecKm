from pydantic import BaseModel
from typing import Optional, List

class AlertDataCreate(BaseModel):
    source_ip: str = ""
    dest_ip: str = ""
    dest_port: str = ""
    protocol: str = ""
    req_header: str = ""
    req_body: str = ""
    res_header: str = ""
    res_body: str = ""
    serialized_log: str = ""  # 用于存放清洗并序列化后的内容


class BatchAnalyzeResponse(BaseModel):
    status: str
    record_ids: List[int]
    total: int
    success_count: int
    failed_count: int


class FeedbackData(BaseModel):
    record_id: int
    is_correct: bool
    human_verified_type: str


class ChatRequest(BaseModel):
    message: str


class HistoryItem(BaseModel):
    id: int
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[str] = None
    protocol: Optional[str] = None
    threat_level: Optional[str] = None
    created_at: Optional[str] = None


class AnalyzeTextRequest(BaseModel):
    log_text: str