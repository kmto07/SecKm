# SecKm - 基于安全大模型的网络告警智能化分析与批研判平台
## 1. 项目基本说明

在现代网络安全运营（SecOps）中，安全设备每天会产生海量的网络流量告警日志。传统特征码匹配机制存在较高的误报率，导致安全分析人员往往陷入“告警疲劳”中。

**SecKm** (Security Knowledge Model) 是一个**基于安全大语言模型（LLM）的智能化网络告警研判平台**。本项目不仅包含前端可视化看板与后端推理服务，还包含了完整的**安全日志数据集处理、模型微调与效果评估闭环**。旨在深度结合传统安全数据治理与前沿 AI 能力，针对批量网络日志（如五元组、HTTP 请求/响应包）提供自动化、专家级的分析与研判支撑。

## 2. 项目目录结构

本项目包含模型训练数据准备、模型评估以及 Web 应用服务三大模块，核心目录结构如下：

```text
.
├── Dataset/                        # 数据集处理、抽样与模型微调脚本目录
│   ├── cluster.py                  # 日志数据聚类脚本（特征提取与分类）
│   ├── sampling.py                 # 数据抽样脚本（均衡正负样本）
│   ├── train.py                    # 大模型微调数据集主脚本
│
├── eval_sec_1/                     # 模型推理评估与指标计算目录
│   ├── calculate_metrics.py        # 评估指标计算脚本
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
```
## 3. 项目声明
* **项目名称**：基于安全大模型的网络告警研判系统
* **项目作者**：Li Song
* **作者单位**：暨南大学网络空间安全学院
* **开发语言**：python
* **框架**：Pytorch、FastAPI、Vue3
* **核心技术**：大模型参数高效微调、深度语义向量化与自适应聚类深层语义表征、结构化思维链数据蒸馏

## 4. 模块展示
**智能对话助手**
<img width="1920" height="869" alt="智能对话助手6" src="https://github.com/user-attachments/assets/23c92fdc-7871-49fc-8090-a49ec641b019" />
**批量上传**
<img width="1917" height="428" alt="批量上传6" src="https://github.com/user-attachments/assets/75302a47-3d96-46fb-ade7-f28dc0b1ce92" />
**研判历史记录**
<img width="1920" height="869" alt="研判历史7" src="https://github.com/user-attachments/assets/befdbef4-8db9-4b97-9564-75fe9a112514" />
<img width="1920" height="869" alt="研判报告8-1" src="https://github.com/user-attachments/assets/e2f099e1-338a-45de-8c99-e0142f3de6de" />
<img width="1920" height="869" alt="研判报告8-2" src="https://github.com/user-attachments/assets/61ca3942-7b8d-4cfe-b9c1-8b3495dda986" />



