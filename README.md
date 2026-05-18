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

**SecKm** (Security Knowledge Model) 是一个**基于安全大语言模型（LLM）的智能化网络告警研判平台**。本项目不仅包含前端可视化看板与后端推理服务，还包含了完整的**安全日志数据集处理、模型微调与效果评估闭环**。旨在深度结合传统安全数据治理与前沿 AI 能力，针对批量网络日志（如五元组、HTTP 请求/响应包）提供自动化、专家级的分析与研判支撑。

---

## 📂 2. 项目目录结构

本项目包含模型训练数据准备、模型评估以及 Web 应用服务三大模块，核心目录结构如下：

```text
.
├── Dataset/                        # 数据集处理、抽样与模型微调脚本目录
│   ├── cluster.py                  # 日志数据聚类脚本（特征提取与分类）
│   ├── clustered_logs_metadata.csv # 聚类后的日志元数据输出
│   ├── sampling.py                 # 数据抽样脚本（均衡正负样本）
│   ├── train.py                    # 大模型微调/训练主脚本
│   ├── train_data_1.json           # 格式化后的训练集数据
│   ├── test_data_1.json            # 格式化后的测试集数据
│   ├── train_seed_data_max5.csv    # 训练集原始种子数据
│   └── test_seed_data_max5.csv     # 测试集原始种子数据
│
├── eval_sec_1/                     # 模型推理评估与指标计算目录
│   ├── calculate_metrics.py        # 评估指标（如准确率、召回率、F1等）计算脚本
│   ├── llamaboard_config.yaml      # 模型评测看板/框架配置文件
│   ├── all_results.json            # 综合评估结果与统计分析
│   ├── generated_predictions.jsonl # 模型在测试集上生成的原始预测输出
│   ├── predict_results.json        # 格式化后的预测对比结果
│   └── running_log.txt             # 评估过程的运行日志
│
└── SecKm/                          # Web 应用核心目录（前后端分离项目）
    ├── backend/                    # 后端 FastAPI 异步服务目录
    │   ├── main.py                 # 全局核心主程序：包含清洗管道、LLM 核心逻辑、API 路由
    │   ├── models.py               # 数据库 ORM 实体层：定义告警记录核心多维字段
    │   ├── schemas.py              # Pydantic 数据模型层：约束输入输出数据流
    │   ├── database.py             # 数据库初始化脚本及 SQLite 引擎配置
    │   ├── requirements.txt        # 后端 Python 依赖清单
    │   └── security_alerts.db      # 运行时自动生成的 SQLite 轻量级关系型数据库
    │
    └── frontend/                   # 前端 Vue3 单页面应用工程目录
        ├── src/
        │   ├── components/
        │   │   └── AlertDashboard.vue  # 核心业务面板：批量研判、智能对话、历史列表
        │   ├── App.vue             # Vue 根组件
        │   ├── main.ts             # 前端 TypeScript 入口文件
        │   └── style.css           # 全局样式表
        ├── package.json            # 前端 Node.js 项目依赖配置文件
        └── vite.config.ts          # Vite 工程打包配置
⚠️ 3. 项目声明
* **项目名称**：基于安全大模型的网络告警研判系统
* **项目作者**：Li Song
* **作者单位**：暨南大学网络空间安全学院
* **开发语言**：python
* **框架**：FastAPI、Vue3
* **核心技术**：
