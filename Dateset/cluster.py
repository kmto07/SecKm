import pandas as pd
import re
import numpy as np
import faiss
from FlagEmbedding import BGEM3FlagModel
from sklearn.cluster import HDBSCAN

# 输入的原始脱敏日志文件路径
INPUT_CSV = "脱敏日志_包含提供字段.csv"
# 导出的包含聚类标签的元数据文件路径
OUTPUT_CSV = "clustered_logs_metadata.csv"
# 导出的 FAISS 向量数据库索引文件路径
OUTPUT_INDEX = "security_logs_vector.index"
# 设置最大处理行数以平衡性能与覆盖面
MAX_ROWS = 20000 


# 阶段 1：数据清洗、智能特征裁剪与序列化
def step1_clean_and_serialize(file_path, nrows=20000):
    print(f" [阶段1] 开始加载并清洗 CSV 数据 (处理行数 {nrows})...")
    
    # 支持多种编码读取以防报错
    try:
        df = pd.read_csv(file_path, encoding='utf-8', on_bad_lines='skip', nrows=nrows)
    except:
        df = pd.read_csv(file_path, encoding='gb18030', on_bad_lines='skip', nrows=nrows)
    
    # 对缺失的关键字段进行默认值填充
    fill_values = {
        '源地址': 'Unknown', '源端口': 0, '目的地址': 'Unknown', '目的端口': 0,
        '应用协议': 'Unknown', '攻击二级类型': 'Unknown',
        '请求头': 'None', '请求体': 'None', '响应头': 'None', '响应体': 'None'
    }
    df.fillna(fill_values, inplace=True)
    
    # 使用正则表达式对 IP 地址进行泛化脱敏处理
    def mask_ip(text):
        text = str(text)
        return re.sub(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', '<IP_ADDR>', text)
    
    df['源地址'] = df['源地址'].apply(mask_ip)
    df['目的地址'] = df['目的地址'].apply(mask_ip)
    
    # 按照安全研判专家思维进行特征提取与序列化
    def serialize_row(row):
        protocol = row['应用协议']
        dest_port = row['目的端口']
        
        # 提取请求头中的核心攻击指纹信息
        raw_req = str(row['请求头'])
        key_req_lines = [
            line.strip() for line in raw_req.split('\n') 
            if line.strip().startswith(('GET', 'POST', 'PUT', 'DELETE', 'User-Agent:', 'Content-Type:', 'Authorization:'))
        ]
        clean_req_headers = '\n'.join(key_req_lines) if key_req_lines else 'None'
        
        # 提取响应头中的服务器指纹信息
        raw_res = str(row['响应头'])
        key_res_lines = [
            line.strip() for line in raw_res.split('\n') 
            if line.strip().startswith(('HTTP/', 'Server:', 'X-Powered-By:'))
        ]
        clean_res_headers = '\n'.join(key_res_lines) if key_res_lines else 'None'

        return (
            f"【服务】协议: {protocol} | 目标端口: {dest_port}\n"
            f"【关键请求头】\n{clean_req_headers}\n"
            f"【请求体】\n{row['请求体']}\n"
            f"【关键响应头】\n{clean_res_headers}\n"
            f"【响应体】\n{row['响应体']}"
        )
    
    df['serialized_log'] = df.apply(serialize_row, axis=1)
    print(f" [阶段1] 数据清洗与特征序列化完成。")
    return df


# BGE M3 向量化与 HDBSCAN 聚类分析
def step2_vectorize_and_cluster(df):
    print("\n [阶段2] 调用 BGE-M3 模型提取 1024 维深层语义特征...")
    # 使用 FP16 模式加速推理并节省显存
    model = BGEM3FlagModel('BAAI/bge-m3', use_fp16=True)
    
    logs_list = df['serialized_log'].tolist()
    # 获得高维向量矩阵
    embeddings = model.encode(logs_list, batch_size=32, max_length=512)['dense_vecs']
    
    print("   -> 正在通过 HDBSCAN 算法自动识别攻击家族簇...")
    clusterer = HDBSCAN(min_cluster_size=5, metric='euclidean')
    df['cluster_label'] = clusterer.fit_predict(embeddings)
    
    noise_count = len(df[df['cluster_label'] == -1])
    cluster_num = df['cluster_label'].nunique() - (1 if noise_count > 0 else 0)
    
    print(f" [阶段2] 聚类完成。识别出 {cluster_num} 个有效攻击簇，剔除噪声 {noise_count} 条。")
    return df, embeddings


# 阶段 3：构建 FAISS 向量索引并保存
def step3_save_faiss_index(embeddings, index_path):
    print("\n [阶段3] 正在构建基于 L2 归一化的 FAISS 检索索引...")
    # 强制转换为 float32 格式以适配 FAISS 引擎
    embeddings = np.array(embeddings, dtype=np.float32)
    dimension = embeddings.shape[1]
    
    # 归一化后执行内积搜索等价于余弦相似度计算
    faiss.normalize_L2(embeddings)
    index = faiss.IndexFlatIP(dimension) 
    index.add(embeddings)
    
    # 将内存中的索引树写入本地磁盘文件
    faiss.write_index(index, index_path)
    print(f" [阶段3] FAISS 库构建完成！共存入 {index.ntotal} 条高维特征。")
    print(f" [阶段3] FAISS 向量库已成功持久化至 {index_path}。")


if __name__ == "__main__":
    # 1. 预处理数据并进行智能裁剪
    processed_df = step1_clean_and_serialize(INPUT_CSV, nrows=MAX_ROWS)
    
    # 2. 提取语义向量并完成自动化聚类定性
    final_df, log_embeddings = step2_vectorize_and_cluster(processed_df)
    
    # 3. 先行导出 CSV 结果文件作为后续检索的元数据关联库
    # 剔除绘图辅助列以保持元数据文件的整洁性
    final_df.to_csv(OUTPUT_CSV, index=False, encoding='utf-8-sig')
    print(f"\n 步骤 1/2 完成。元数据已导出至 {OUTPUT_CSV}")
    
    # 4. 构建并保存 FAISS 向量索引文件以支持线上的 RAG 实时研判
    step3_save_faiss_index(log_embeddings, OUTPUT_INDEX)
    print(f" 步骤 2/2 完成。向量库已保存至 {OUTPUT_INDEX}")
    
    print(f"\n 全链路数据治理流水线执行完毕！")