# rf4-key-server

俄钓助手 - 卡密在线验证服务器

## 部署

已部署到 Render.com

验证接口：`https://rf4-key-server.onrender.com/activate`

## 本地测试

```bash
pip install -r requirements.txt
python server.py
```

## 生成卡密

```bash
python ../key_server/gen_keys.py 1 15
```
