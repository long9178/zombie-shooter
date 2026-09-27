# 僵尸枪战后端

需要 Node.js 18 或更新版本，无需安装第三方依赖。

```powershell
npm start
```

浏览器访问 `http://127.0.0.1:3000`。账号、密码哈希、会话和游戏存档保存在运行目录下的 `data/database.json`；密码使用服务端 scrypt 哈希，登录 Cookie 为 HttpOnly。

服务默认只监听本机地址。对外部署前应使用 HTTPS 反向代理，并按部署环境调整监听地址和数据文件备份策略。JSON 文件存储适用于单实例运行，不适合多个服务进程同时写入。

HTTPS 代理终止 TLS 时，请通过环境变量 `COOKIE_SECURE=true` 启用安全 Cookie；如需从其他设备访问，可将 `HOST` 设置为 `0.0.0.0`。数据目录可通过 `DATA_DIRECTORY` 指定。