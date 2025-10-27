# SafeGen — 强密码随机生成器 (Python/Tkinter)

## 功能
- 三种候选策略：①强密码 ②长字母数字 ③分段易记（4位一段）
- 模板驱动（含“银行模式”）
- 密码熵（bits）可视化
- 一键复制 + 剪贴板自动清除（可设 5–120s）
- 本地保险库（AES-GCM，主密码保护），加载后自动填充
- Windows 可打包单 exe

> 设计遵循：本地生成、不上传网络；使用 CSPRNG；AES-GCM 本地加密等。  
> 参考：你的《强密码随机生成器》与《需求说明书》。:contentReference[oaicite:3]{index=3} :contentReference[oaicite:4]{index=4}

## 运行
```bash
pip install -r requirements.txt
python main.py
