from __future__ import annotations

import csv
import io
import json
import os
import re
import datetime
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from openai import AsyncOpenAI
from sqlalchemy.orm import Session

import database
import models
import schemas

models.Base.metadata.create_all(bind=database.engine)
database.init_db()

app = FastAPI(title="Security AI Copilot API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

LLM_BASE_URL = os.getenv("LLM_BASE_URL", "http://127.0.0.1:8000/v1")
LLM_MODEL_NAME = os.getenv("LLM_MODEL_NAME", "gpt-3.5-turbo")
llm_client = AsyncOpenAI(api_key=os.getenv("LLM_API_KEY", "EMPTY"), base_url=LLM_BASE_URL)

THREAT_LEVELS = ["高危", "中危", "低危", "安全"]
ATTACK_TYPES = ["SQL注入", "XSS", "目录穿越", "命令执行", "弱口令", "端口扫描", "暴力破解", "反序列化", "SSRF", "恶意上传", "钓鱼", "木马", "正常流量", "未知"]
REPORT_PATTERNS = {
    "initial_observation": r"【初步观察】：\s*(.*?)(?=\n【|\Z)",
    "deep_analysis": r"【载荷深度分析】：\s*(.*?)(?=\n【|\Z)",
    "final_conclusion": r"【最终结论】：\s*(.*?)(?=\n【|\Z)",
    "threat_level": r"【威胁等级】：\s*([^\n<]+)",
    "suggestions": r"【处理建议】：\s*(.*?)(?=\n【|\Z)",
}

CSV_INPUT_MAPPING = {
    "source_ip": ["source_ip", "src_ip", "源地址", "source", "ip_src"],
    "dest_ip": ["dest_ip", "dst_ip", "目的地址", "destination", "ip_dst"],
    "dest_port": ["dest_port", "port", "目的端口", "dst_port", "源端口"],
    "protocol": ["protocol", "service", "应用协议", "proto"],
    "req_header": ["req_header", "request_header", "请求头", "header"],
    "req_body": ["req_body", "request_body", "请求体", "log", "raw", "input", "content", "message", "text", "payload"],
    "res_header": ["res_header", "response_header", "响应头", "response_head"],
    "res_body": ["res_body", "response_body", "响应体", "output", "answer"],
}


def extract_threat_level(text: str) -> str:
    match = re.search(REPORT_PATTERNS["threat_level"], text or "", re.S)
    if match:
        candidate = match.group(1).strip()
        for level in THREAT_LEVELS:
            if level in candidate:
                return level
    normalized = (text or "").lower()
    if any(keyword in normalized for keyword in ["critical", "high", "危险", "入侵", "攻击", "恶意", "利用成功"]):
        return "高危"
    if any(keyword in normalized for keyword in ["medium", "中危", "可疑", "异常", "风险"]):
        return "中危"
    if any(keyword in normalized for keyword in ["low", "低危", "提示", "观察"]):
        return "低危"
    return "安全"


def extract_attack_type(text: str) -> str:
    normalized = text or ""
    for attack in ATTACK_TYPES:
        if attack in normalized:
            return attack
    return "未知"


def extract_section(text: str, key: str) -> str:
    pattern = REPORT_PATTERNS.get(key)
    if not pattern:
        return ""
    match = re.search(pattern, text or "", re.S)
    if not match:
        return ""
    return match.group(1).strip()


def extract_report_fields(text: str) -> dict[str, str]:
    report = {
        "initial_observation": extract_section(text, "initial_observation"),
        "deep_analysis": extract_section(text, "deep_analysis"),
        "final_conclusion": extract_section(text, "final_conclusion"),
        "suggestions": extract_section(text, "suggestions"),
    }
    report["threat_level"] = extract_threat_level(text)
    report["attack_type"] = extract_attack_type(text)
    return report


def extract_report_text(report: dict[str, str]) -> str:
    return (
        f"【初步观察】：{report.get('initial_observation', '')}\n\n"
        f"【载荷深度分析】：{report.get('deep_analysis', '')}\n\n"
        f"【最终结论】：{report.get('final_conclusion', '')}\n\n"
        f"【威胁等级】：{report.get('threat_level', '')}\n\n"
        f"【处理建议】：{report.get('suggestions', '')}"
    )


def build_prompt(data: schemas.AlertDataCreate) -> str:
    req_header = truncate_text(data.req_header, 1200)
    req_body = truncate_text(data.req_body, 3000)
    res_header = truncate_text(data.res_header, 1200)
    res_body = truncate_text(data.res_body, 1800)
    return (
        "作为高级安全分析专家，请独立研判以下网络流量日志是否存在安全威胁，给出详尽的逻辑推导过程及对应的处理建议。\n"
        f"【服务】协议: {truncate_text(data.protocol, 100)} | 目标端口: {truncate_text(data.dest_port, 50)}\n"
        f"【源地址】源IP: {truncate_text(data.source_ip, 80)} | 目的IP: {truncate_text(data.dest_ip, 80)}\n"
        f"【关键请求头】\n{req_header}\n"
        f"【请求体】\n{req_body}\n"
        f"【关键响应头】\n{res_header}\n"
        f"【响应体】\n{res_body}\n"
        "请严格按照以下格式输出：\n"
        "【初步观察】：一句话简述目标端口、核心路径与请求方式，并明确指出请求头中是否存在明显的扫描器指纹或伪造异常。\n"
        "【载荷深度分析】：\n"
        "1. 攻击链概述：将攻击者的意图与载荷拆解为清晰的执行阶段。\n"
        "2. 技术拆解：深入剖析载荷中的特定指令、函数或特殊字符的攻击原理。\n"
        "【最终结论】：直接给出明确的研判结论。\n"
        "【威胁等级】：必须且仅能输出以下四个词汇之一（高危、中危、低危、安全）。\n"
        "【处理建议】：针对该研判结论，给出具体且可落地的安全运维处置建议。必须为每条建议明确标注优先级。"
    )


def sanitize_text(value: Any) -> str:
    return "" if value is None else str(value)


def truncate_text(value: Any, limit: int = 1800) -> str:
    text = sanitize_text(value).replace("\r\n", "\n")
    return text if len(text) <= limit else text[:limit] + "…"


def get_row_value(row: dict[str, Any], keys: list[str]) -> str:
    for key in keys:
        if key in row and row.get(key) not in (None, ""):
            return sanitize_text(row.get(key))
    return ""


def normalize_csv_row(row: dict[str, Any]) -> schemas.AlertDataCreate:
    return schemas.AlertDataCreate(
        source_ip=get_row_value(row, CSV_INPUT_MAPPING["source_ip"]),
        dest_ip=get_row_value(row, CSV_INPUT_MAPPING["dest_ip"]),
        dest_port=get_row_value(row, CSV_INPUT_MAPPING["dest_port"]),
        protocol=get_row_value(row, CSV_INPUT_MAPPING["protocol"]),
        req_header=get_row_value(row, CSV_INPUT_MAPPING["req_header"]),
        req_body=get_row_value(row, CSV_INPUT_MAPPING["req_body"]),
        res_header=get_row_value(row, CSV_INPUT_MAPPING["res_header"]),
        res_body=get_row_value(row, CSV_INPUT_MAPPING["res_body"]),
    )


def parse_batch_file(filename: str, content: bytes) -> list[schemas.AlertDataCreate]:
    suffix = os.path.splitext(filename or "")[1].lower()
    text = content.decode("utf-8", errors="ignore")
    records: list[schemas.AlertDataCreate] = []

    if suffix != ".csv":
        raise HTTPException(status_code=400, detail="当前版本仅支持 CSV 文件批量研判")

    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        return []
    for row in reader:
        records.append(normalize_csv_row(row))
    return records


async def call_llm(prompt: str, system_prompt: str) -> str:
    response = await llm_client.chat.completions.create(
        model=LLM_MODEL_NAME,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        temperature=0.1,
        max_tokens=1200,
    )
    return response.choices[0].message.content or ""


def save_record(db: Session, data: schemas.AlertDataCreate, ai_text: str, status: str = "analyzed") -> models.AlertRecord:
    parsed = extract_report_fields(ai_text)
    record = models.AlertRecord(
        source_ip=data.source_ip,
        dest_ip=data.dest_ip,
        dest_port=data.dest_port,
        protocol=data.protocol,
        req_header=data.req_header,
        req_body=data.req_body,
        res_header=data.res_header,
        res_body=data.res_body,
        ai_raw_response=extract_report_text(parsed) or ai_text,
        ai_attack_type=parsed["attack_type"],
        threat_level=parsed["threat_level"],
        initial_observation=parsed["initial_observation"],
        deep_analysis=parsed["deep_analysis"],
        final_conclusion=parsed["final_conclusion"],
        suggestions=parsed["suggestions"],
        status=status,
        created_at=datetime.datetime.now() # 准确生成入库时间
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


@app.get("/api/v1/health")
def health_check():
    return {"status": "ok"}


@app.get("/api/v1/model-health")
async def model_health():
    try:
        response = await llm_client.chat.completions.create(
            model=LLM_MODEL_NAME,
            messages=[{"role": "user", "content": "请只回复：ok"}],
            temperature=0.1,
            max_tokens=8,
        )
        return {"status": "ok", "models": [LLM_MODEL_NAME], "reply": response.choices[0].message.content}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"模型服务不可用: {exc}") from exc


# 【核心修改点】：列表接口只返回你需要的极简属性，无需 ATTACK_TYPES
@app.get("/api/v1/records")
def list_records(db: Session = Depends(database.get_db)):
    records = db.query(models.AlertRecord).order_by(models.AlertRecord.id.desc()).all()
    return [
        {
            "id": r.id,
            "protocol": r.protocol,
            "dest_port": r.dest_port,
            "threat_level": r.threat_level,
            "created_at": r.created_at.strftime("%Y-%m-%d %H:%M:%S") if r.created_at else None,
        }
        for r in records
    ]


@app.get("/api/v1/records/{record_id}")
def get_record(record_id: int, db: Session = Depends(database.get_db)):
    record = db.query(models.AlertRecord).filter(models.AlertRecord.id == record_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="记录不存在")
    parsed = {
        "initial_observation": record.initial_observation or "",
        "deep_analysis": record.deep_analysis or "",
        "final_conclusion": record.final_conclusion or "",
        "suggestions": record.suggestions or "",
        "threat_level": record.threat_level or extract_threat_level(record.ai_raw_response or ""),
        "attack_type": record.ai_attack_type or extract_attack_type(record.ai_raw_response or ""),
    }
    return {
        "id": record.id,
        "source_ip": record.source_ip,
        "dest_ip": record.dest_ip,
        "dest_port": record.dest_port,
        "protocol": record.protocol,
        "req_header": record.req_header,
        "req_body": record.req_body,
        "res_header": record.res_header,
        "res_body": record.res_body,
        "ai_raw_response": record.ai_raw_response,
        "ai_attack_type": record.ai_attack_type,
        "threat_level": record.threat_level,
        "status": record.status,
        "created_at": record.created_at.strftime("%Y-%m-%d %H:%M:%S") if record.created_at else None,
        "report": parsed,
    }


@app.post("/api/v1/analyze")
async def analyze_alert(data: schemas.AlertDataCreate, db: Session = Depends(database.get_db)):
    try:
        prompt = build_prompt(data)
        ai_text = await call_llm(
            prompt,
            "你是一名精通网络流量、Web攻击、数据库攻击和告警研判的高级安全分析专家。你需要严格按照指定结构输出研判结果。",
        )
        record = save_record(db, data, ai_text)
        parsed = extract_report_fields(ai_text)
        return {
            "status": "success",
            "record_id": record.id,
            "ai_response": extract_report_text(parsed) or ai_text,
            "threat_level": record.threat_level,
            "ai_attack_type": record.ai_attack_type,
            "report": parsed,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"模型调用失败: {exc}") from exc


@app.post("/api/v1/chat")
async def chat_with_ai(data: schemas.ChatRequest):
    try:
        prompt = (
            "用户将直接输入单条网络日志，请你判断是否存在威胁，并给出简洁结论。\n"
            f"日志内容：\n{data.message}\n"
            "请严格按照指定结构输出最终结论、威胁等级、攻击类型和处理建议。"
        )
        ai_text = await call_llm(
            prompt,
            "你是一名网络安全研判助手，擅长对单条日志做快速准确分析，输出必须便于前端展示。",
        )
        parsed = extract_report_fields(ai_text)
        return {
            "status": "success",
            "reply": ai_text,
            "threat_level": parsed["threat_level"],
            "ai_attack_type": parsed["attack_type"],
            "report": parsed,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"模型调用失败: {exc}") from exc


@app.post("/api/v1/batch-analyze")
async def batch_analyze(file: UploadFile = File(...), db: Session = Depends(database.get_db)):
    try:
        content = await file.read()
        items = parse_batch_file(file.filename or "", content)
        if not items:
            raise HTTPException(status_code=400, detail="文件内容为空或无法解析")

        record_ids: list[int] = []
        failed_items: list[dict[str, Any]] = []
        for index, item in enumerate(items, start=1):
            try:
                prompt = build_prompt(item)
                ai_text = await call_llm(
                    prompt,
                    "你是一名高级网络安全研判专家。请严格按照指定结构输出研判结论，明确包含威胁等级与处理建议。",
                )
                record = save_record(db, item, ai_text)
                record_ids.append(record.id)
            except Exception as exc:
                fallback_text = (
                    "【初步观察】：批量研判失败，无法获取模型输出。\n\n"
                    "【载荷深度分析】：模型调用或结果解析过程中发生异常，已保留原始日志待人工复核。\n\n"
                    "【最终结论】：当前条目未能完成自动研判，请检查模型服务或输入长度。\n\n"
                    "【威胁等级】：低危\n\n"
                    "【处理建议】：[高优先级] 检查模型服务与 API 连通性；[中优先级] 检查该条日志长度并尝试裁剪后重试；[低优先级] 将失败条目加入人工复核队列。"
                )
                fallback_record = models.AlertRecord(
                    source_ip=item.source_ip,
                    dest_ip=item.dest_ip,
                    dest_port=item.dest_port,
                    protocol=item.protocol,
                    req_header=item.req_header,
                    req_body=item.req_body,
                    res_header=item.res_header,
                    res_body=item.res_body,
                    ai_raw_response=fallback_text,
                    ai_attack_type="未知",
                    threat_level="低危",
                    initial_observation="批量研判失败，无法获取模型输出。",
                    deep_analysis="模型调用或结果解析过程中发生异常，已保留原始日志待人工复核。",
                    final_conclusion="当前条目未能完成自动研判，请检查模型服务或输入长度。",
                    suggestions="[高优先级] 检查模型服务与 API 连通性；[中优先级] 检查该条日志长度并尝试裁剪后重试；[低优先级] 将失败条目加入人工复核队列。",
                    status="failed",
                    created_at=datetime.datetime.now() # 兜底数据也确保有正确的时间生成
                )
                db.add(fallback_record)
                db.commit()
                db.refresh(fallback_record)
                record_ids.append(fallback_record.id)
                failed_items.append({"index": index, "detail": str(exc), "record_id": fallback_record.id})

        return {
            "status": "success",
            "record_ids": record_ids,
            "total": len(items),
            "success_count": len(record_ids),
            "failed_count": len(failed_items),
            "failed_items": failed_items,
        }
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"批量研判失败: {exc}") from exc


@app.post("/api/v1/analyze-text")
async def analyze_text(data: schemas.AnalyzeTextRequest, db: Session = Depends(database.get_db)):
    payload = schemas.AlertDataCreate(req_body=data.log_text)
    return await analyze_alert(payload, db)


@app.post("/api/v1/feedback")
def submit_feedback(feedback: schemas.FeedbackData, db: Session = Depends(database.get_db)):
    record = db.query(models.AlertRecord).filter(models.AlertRecord.id == feedback.record_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="记录不存在")
    record.human_verified_type = feedback.human_verified_type
    record.status = "auto_resolved" if feedback.is_correct else "human_corrected"
    db.commit()
    return {"status": "success"}