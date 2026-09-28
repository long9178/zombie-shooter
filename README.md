# 僵尸枪战后端

需要 Node.js 18 或更新版本，无需安装第三方依赖。

```powershell
npm start
```

首次创建管理员账号前，先停止现有服务并在 PowerShell 设置管理员信息；密码通过隐藏输入读取，不要把真实密码写进代码或提交到版本库：

```powershell
$env:ADMIN_USERNAME = "admin"
$securePassword = Read-Host "管理员密码" -AsSecureString
$env:ADMIN_PASSWORD = ([System.Net.NetworkCredential]::new("", $securePassword)).Password
npm start
```

管理员账号会写入 `data/database.json`，密码仍以 scrypt 哈希保存。管理员名必须尚未被普通账号注册；账号已存在时服务会拒绝引导，需换一个未占用的账号名。之后可直接登录，在“玩家管理”中查看账号并删除玩家账号。

本机浏览器访问 `http://127.0.0.1:3000`。局域网联机时，房主和好友都要连接同一个局域网；房主使用电脑的局域网 IPv4 地址打开游戏（例如 `http://192.168.1.20:3000`），然后在“联机邀请”中选择好友创建房间并分享邀请链接或房间码。受邀玩家登录好友账号后接受邀请或输入房间码。首次联机时，Windows 防火墙可能需要允许 Node.js 接收专用网络连接。房间最多 4 人；房主结束房间或离线后，房间关闭。

账号、密码哈希、找回答案哈希、会话和游戏存档保存在运行目录下的 `data/database.json`；密码及好友名称答案均使用服务端 scrypt 哈希，不保存明文，登录 Cookie 为 HttpOnly。忘记密码时可用注册时填写的好友名称验证；升级前已注册的账号，登录后需先设置找回验证。服务器默认监听 `0.0.0.0`，可通过环境变量 `HOST` 和 `PORT` 调整。对外部署前应使用 HTTPS 反向代理，并按部署环境调整监听地址和数据文件备份策略。JSON 文件存储适用于单实例运行，不适合多个服务进程同时写入。

HTTPS 代理终止 TLS 时，请通过环境变量 `COOKIE_SECURE=true` 启用安全 Cookie。数据目录可通过 `DATA_DIRECTORY` 指定。