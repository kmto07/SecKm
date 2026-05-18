import pandas as pd
import json
import time
import threading
from openai import OpenAI
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm

#  直接读取上一步生成的干净训练集
INPUT_CSV = "test_seed_data_max5_200.csv"       
OUTPUT_JSON = "test_data_1.json" # 建议改名为 train_data 以区分测试集
#  大模型 API 配置 
API_KEY = "*******" 
BASE_URL = "https://api.siliconflow.cn/v1"      
MODEL_NAME = "Pro/deepseek-ai/DeepSeek-V3.2"                  

#  并发配置
MAX_WORKERS = 5               # 并发请求大模型的线程数

# API 蒸馏与实时流式写入
# 准备一个全局列表和一把线程锁，用于保障文件写入安全
alpaca_dataset = []
file_write_lock = threading.Lock()

def save_checkpoint(output_path):
    """线程安全的文件保存函数"""
    with file_write_lock:
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(alpaca_dataset, f, ensure_ascii=False, indent=2)

def process_and_stream_save(df):
    print(" 开始并发请求大模型 API，并实时保存至本地文件...")
    client = OpenAI(api_key=API_KEY, base_url=BASE_URL)
    
    PROMPT_TEMPLATE = """
你是一名顶级的网络安全分析专家。请仔细分析以下经过特征裁剪的网络流量日志，并独立判断其是否存在攻击行为。
注意：请完全基于日志本身的特征进行客观分析，不要受到任何外部先入为主的干扰。

请严格按照以下思维链格式输出你的研判报告：
【初步观察】：一句话简述目标端口、核心路径与请求方式，并明确指出请求头中是否存在明显的扫描器指纹或伪造异常。
【载荷深度分析】：
1. 攻击链概述：将攻击者的意图与载荷拆解为清晰的执行阶段（如：阶段1：探测与注入构造 -> 阶段2：载荷投递与执行 -> 阶段3：后渗透动作）。
2. 技术拆解：结合上述阶段，深入剖析载荷中的特定指令、函数或特殊字符的攻击原理。若为明确的高危恶意载荷（如木马下载、反弹Shell）或已被安全设备明确拦截，请直接进行深度技术拆解，无需进行多余的“误报排除”解释；若特征模糊，再论述正常业务特征进行对比。
【最终结论】：直接给出明确的研判结论，指明具体的攻击名称（如：针对GPON设备的远程命令注入攻击），并用一句话概括核心判定依据。
【威胁等级】：必须且仅能输出以下四个词汇之一（高危、中危、低危、安全）。为防止定性冲突，请严格遵循以下强制基线标准：
- 高危：存在明确的漏洞利用代码（如远程命令执行RCE、SQL注入、反序列化等载荷），且具备较高破坏性。
- 中危：敏感目录爆破、越权尝试、或针对特定业务逻辑的攻击探测。
- 低危：仅为盲目的端口扫描、由于白名单阻断导致的连接拒绝（如 Host not allowed to connect）、未携带任何实质性攻击载荷的初始握手失败。
- 安全：完全合法的标准业务交互。
【处理建议】：针对该研判结论，给出具体且可落地的安全运维处置建议。必须为每条建议明确标注优先级（严格使用格式：[高优先级]、[中优先级]、[低优先级]），并按照优先级从高到低的顺序排列。

网络日志内容如下：
{log_content}
"""

    def fetch_cot_logic(row):
        prompt = PROMPT_TEMPLATE.format(
            log_content=row['serialized_log']
        )
        try:
            response = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {"role": "system", "content": "你是一个逻辑严密、客观公正的网络安全专家系统。"},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2 
            )
            return row.name, response.choices[0].message.content
        except Exception as e:
            return row.name, f"ERROR: {str(e)}"

    success_count = 0
    fail_count = 0

    # 启动并发线程池
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(fetch_cot_logic, row): row for _, row in df.iterrows()}
        
        for future in tqdm(as_completed(futures), total=len(futures), desc="API 蒸馏与写入进度"):
            idx, result = future.result()
            row = df.loc[idx]
            
            if result and not result.startswith("ERROR:"):
                #  1. 组装成 LLaMA-Factory 兼容的 Alpaca 格式
                data_point = {
                    "instruction": "作为高级安全分析专家，请独立研判以下网络流量日志是否存在安全威胁，给出详尽的逻辑推导过程及对应的处理建议。",
                    "input": row['serialized_log'],
                    "output": result
                }
                
                #  2. 加入全局列表
                alpaca_dataset.append(data_point)
                
                #  3. 实时覆写到 JSON 文件（被线程锁保护）
                save_checkpoint(OUTPUT_JSON)
                
                success_count += 1
            else:
                fail_count += 1
                print(f"\n 警告：索引 {idx} 数据请求失败 -> {result}")
            
            time.sleep(0.1) # 增加微小延迟，防止触发 API 限流

    print(f"\n 任务全部结束！")
    print(f" 统计情况：成功 {success_count} 条，失败 {fail_count} 条。")
    print(f" 微调数据集已安全保存至: {OUTPUT_JSON}")

if __name__ == "__main__":
    print(f" 正在直接读取纯净种子文件: {INPUT_CSV} ...")
    try:
        df = pd.read_csv(INPUT_CSV, encoding='utf-8-sig', on_bad_lines='skip')
    except UnicodeDecodeError:
        df = pd.read_csv(INPUT_CSV, encoding='gb18030', on_bad_lines='skip')
    
    if 'serialized_log' not in df.columns:
        raise ValueError(" 错误：CSV文件中缺少必要的 'serialized_log' 列！请检查输入文件。")
        
    print(f" 成功加载 {len(df)} 条纯净数据，准备开始蒸馏！\n")
    
    # 边调用大模型边组装，边安全写入文件
    process_and_stream_save(df)