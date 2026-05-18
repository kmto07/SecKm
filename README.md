# SecKm - 基于安全大模型的网络告警智能化分析与批研判平台

<p align="center">
  <img src="https://img.shields.io/badge/Frontend-Vue%203%20%7C%20TypeScript-42b883?style=flat-square&logo=vue.js" alt="Frontend">
  <img src="https://img.shields.io/badge/UI_Library-Element%20Plus-409EFF?style=flat-square&logo=element-plus" alt="UI Library">
  <img src="https://img.shields.io/badge/Backend-FastAPI%20%7C%20Python-009688?style=flat-square&logo=fastapi" alt="Backend">
  <img src="https://img.shields.io/badge/Database-SQLite%20%7C%20SQLAlchemy-003B57?style=flat-square&logo=sqlite" alt="Database">
  <img src="https://img.shields.io/badge/Data_Process-Pandas-150458?style=flat-square&logo=pandas" alt="Pandas">
</p>

## 📖 1. 项目基本说明

在现代网络安全运营（SecOps）中，安全设备每天会产生海量的网络流量告警日志。传统特征码匹配机制存在较高的误报率，导致安全分析人员往往陷入“告警疲劳”中。

**SecKm** (Security Knowledge Model) 是一个**基于安全大语言模型（LLM）的智能化网络告警研判平台**。本项目旨在深度结合传统安全数据治理与前沿 AI 能力，针对批量网络日志（如五元组、HTTP 请求/响应包）提供自动化、专家级的分析与研判支撑。

### ✨ 核心功能亮点
* **智能化数据清洗与特征裁剪**：内置基于 `Pandas` 的数据处理引擎，自动过滤冗余网络噪点（如无用标头），定向提取具有攻击指纹的字段，大幅节省大模型 Token 消耗。
* **隐私数据泛化脱敏**：利用正则引擎对 CSV 报文中的真实 IP 地址进行 `<IP_ADDR>` 泛化替换，确保内部网络拓扑和企业资产隐私不泄露。
* **极简高效的研判看板**：专为一线运营人员裁剪的界面，摒弃冗杂信息，核心历史列表仅聚焦于 **时间、协议、端口、威胁等级** 四大关键维度，并支持一键下钻查看带优先级的修补建议报告。
* **双模式研判引擎**：
  * **批量上传研判**：支持导入 `.csv` 文件，系统自动并发推入模型分析并生成历史记录。
  * **智能对话助手**：支持手动粘贴单条模糊报文或 payload 进行即时对话研判。

---

## 📂 2. 项目目录结构

本项目采用前后端分离架构，核心目录结构如下：

```text
SecKm/
├── backend/                        # 后端 FastAPI 异步服务目录
│   ├── main.py                     # 全局核心主程序：包含清洗管道、LLM 核心逻辑、API 路由
│   ├── models.py                   # 数据库 ORM 实体层：定义告警记录核心多维字段
│   ├── schemas.py                  # Pydantic 数据模型层：约束输入输出数据流
│   ├── database.py                 # 数据库初始化脚本及 SQLite 引擎配置
│   ├── requirements.txt            # 后端 Python 依赖清单
│   └── security_alerts.db          # 运行时自动生成的 SQLite 轻量级关系型数据库
│
└── frontend/                       # 前端 Vue3 单页面应用工程目录
    ├── src/
    │   ├── components/
    │   │   └── AlertDashboard.vue  # 核心业务面板：批量研判、智能对话、历史列表
    │   ├── App.vue                 # Vue 根组件
    │   ├── main.ts                 # 前端 TypeScript 入口文件
    │   └── style.css               # 全局样式表
    ├── package.json                # 前端 Node.js 项目依赖配置文件
    └── vite.config.ts              # Vite 工程打包配置
