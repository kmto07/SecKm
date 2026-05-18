import pandas as pd
import re


# 输入文件：经过 BGE-M3 和 HDBSCAN 聚类后打上标签的原始文件
INPUT_CSV = "clustered_logs_metadata.csv"       

# 输出文件：切分后的训练集与测试集
OUTPUT_TRAIN_CSV = "train_seed_data_max4.csv" 
OUTPUT_TEST_CSV = "test_seed_data_max4.csv"

# 采样配置
MAX_SAMPLES_PER_CLUSTER = 4   # 每个攻击簇最多抽取的样本数，保障多样性

# 生成正则泛化签名

def generate_log_signature(log_text):
    """
    通过正则表达式，将日志中动态变化的 IP、端口、随机数和十六进制底层乱码泛化，
    从而提取出日志的“核心骨架”，用于识别高度同质化的样本。
    """
    if not isinstance(log_text, str):
        return ""
    
    # 1. 替换所有 IP 地址为 <IP>
    sig = re.sub(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', '<IP>', log_text)
    
    # 2. 替换所有底层十六进制或二进制乱码 (如 \xff, \x04) 为 <HEX>
    sig = re.sub(r'\\x[0-9a-fA-F]{2}', '<HEX>', sig)
    
    # 3. 替换所有连续数字 (如动态端口号、时间戳、Content-Length) 为 <NUM>
    sig = re.sub(r'\b\d+\b', '<NUM>', sig)
    
    # 4. 压缩多余的空格和换行，保持结构紧凑
    sig = re.sub(r'\s+', ' ', sig).strip()
    
    return sig

# 核心业务流：加载数据、泛化去重、均衡采样与切分
def prepare_distillation_data(input_path, train_output_path, test_output_path):
    print(f"🚀 开始读取聚类结果文件: {input_path} ...")
    try:
        df = pd.read_csv(input_path, encoding='utf-8-sig', on_bad_lines='skip')
    except UnicodeDecodeError:
        df = pd.read_csv(input_path, encoding='gb18030', on_bad_lines='skip')
    
    total_rows = len(df)
    
    if 'cluster_label' not in df.columns or 'serialized_log' not in df.columns:
        raise ValueError(" 错误：CSV文件中缺少必要的 'cluster_label' 或 'serialized_log' 列！")
        
    # ------------------------------------------
    # 1. 剔除离群噪声点 (Label = -1)
    # ------------------------------------------
    clean_df = df[df['cluster_label'] != -1].copy()
    noise_count = total_rows - len(clean_df)
    print(f" [预处理] 成功剔除聚类噪声数据 {noise_count} 条。")
    
    # ------------------------------------------
    # 2. 严格的正则泛化去重逻辑
    # -----------------------------------------
    print(" 正在计算日志结构签名并执行泛化去重...")
    clean_df['log_signature'] = clean_df['serialized_log'].apply(generate_log_signature)
    
    before_dedup = len(clean_df)
    # 基于生成的结构签名进行去重，保留每种攻击骨架的第一条记录
    clean_df = clean_df.drop_duplicates(subset=['log_signature'])
    after_dedup = len(clean_df)
    
    print(f" [去重] 发现并剔除了 {before_dedup - after_dedup} 条高度同质化的冗余废料。")
    print(f"   -> 当前剩余独一无二的攻击特征模板: {after_dedup} 条。")

    # ------------------------------------------
    # 3. 基于聚类簇的均衡采样
    # ------------------------------------------
    print(f" 正在执行分层均衡采样 (每簇最多 {MAX_SAMPLES_PER_CLUSTER} 条)...")
    sampled_df = clean_df.groupby('cluster_label', group_keys=False).apply(
        lambda x: x.sample(n=min(len(x), MAX_SAMPLES_PER_CLUSTER), random_state=42)
    ).reset_index(drop=True)
    
    # ------------------------------------------
    # 4. 执行分层抽样，构建训练集与测试集
    # ------------------------------------------
    print("\n 正在执行分层抽样，切分训练集与测试集...")
    train_list = []
    test_list = []

    for cluster_id, group in sampled_df.groupby('cluster_label'):
        # 核心修改：如果该簇数据量 >= 5，抽出最后 1 条进测试集，其余进训练集
        if len(group) >= 4:
            train_list.append(group.iloc[:-1])
            test_list.append(group.iloc[-1:])
        # 否则 (1~4条)，全部塞进训练集，保障罕见特征的学习优先级
        else:
            train_list.append(group)

    train_df = pd.concat(train_list).reset_index(drop=True) if train_list else pd.DataFrame()
    test_df = pd.concat(test_list).reset_index(drop=True) if test_list else pd.DataFrame()

    print(f" 数据集切分完成！")
    print(f"   -> 训练集 (Train): {len(train_df)} 条 (用于后续大模型微调)")
    print(f"   -> 测试集 (Test):  {len(test_df)} 条 (用于微调后的效果评估)")

    # ------------------------------------------
    # 5. 导出为最终的蒸馏种子文件
    # ------------------------------------------
    # 导出时把辅助计算的 log_signature 列删掉，保持文件干净
    if not train_df.empty:
        train_df.drop(columns=['log_signature'], errors='ignore').to_csv(train_output_path, index=False, encoding='utf-8-sig')
    if not test_df.empty:
        test_df.drop(columns=['log_signature'], errors='ignore').to_csv(test_output_path, index=False, encoding='utf-8-sig')
    
    print(f"\n 阶段 1 数据准备全部完成！")
    print(f" 训练集已落盘至: {train_output_path}")
    print(f" 测试集已落盘至: {test_output_path}")

if __name__ == "__main__":
    prepare_distillation_data(INPUT_CSV, OUTPUT_TRAIN_CSV, OUTPUT_TEST_CSV)