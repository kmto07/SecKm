import json
import re
from sklearn.metrics import classification_report, accuracy_score

# 1. 预测文件路径
file_path = "generated_predictions.jsonl"

y_true = []
y_pred = []

# 正则表达式：找到【威胁等级】：后面的所有内容
pattern = r"【威胁等级】：\s*([^\n<]+)" 

# 🌟 新增的核心清洗函数 🌟
def clean_label(text):
    # 1. 强行删掉可能出现的 markdown 星号、空格、引号等
    text = text.replace('*', '').replace('"', '').replace('\'', '').strip()
    # 2. 无论模型后面跟着写了多少废话，我们只无情地截取最前面的 2 个字符！
    return text[:2]

print("正在解析并清洗模型预测结果...")
try:
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            data = json.loads(line)
            label_text = data.get("label", "")
            predict_text = data.get("predict", "")
            
            true_match = re.search(pattern, label_text)
            pred_match = re.search(pattern, predict_text)
            
            if true_match and pred_match:
                # 提取并丢进清洗函数
                clean_true = clean_label(true_match.group(1))
                clean_pred = clean_label(pred_match.group(1))
                
                # 建立白名单，只有这四个词才会被统计
                valid_labels = ["安全", "低危", "中危", "高危"]
                
                # 如果清洗后是标准的等级，就录入成绩单
                if clean_true in valid_labels and clean_pred in valid_labels:
                    y_true.append(clean_true)
                    y_pred.append(clean_pred)
                else:
                    print(f"⚠️ 丢弃一条严重乱答的脏数据: Pred='{clean_pred}'")

    print("\n" + "="*45)
    print("🎯 大模型网络安全研判分类性能报告 (清洗后)")
    print("="*45)
    
    accuracy = accuracy_score(y_true, y_pred)
    print(f"【整体准确率 (Accuracy)】: {accuracy:.4f}\n")
    
    # 为了让表格按严重程度排序，我们固定 labels 的顺序
    target_names = ["安全", "低危", "中危", "高危"]
    report = classification_report(y_true, y_pred, labels=target_names, digits=4, zero_division=0)
    print(report)

except FileNotFoundError:
    print(f"❌ 找不到文件，请检查路径！")
except Exception as e:
    print(f"❌ 发生未知错误: {e}")