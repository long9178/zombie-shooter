const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const { promisify } = require('node:util');
const { randomBytes, scrypt: scryptCallback, timingSafeEqual, createHash } = require('node:crypto');

const scrypt = promisify(scryptCallback);
const HOST = process.env.HOST || '127.0.0.1';
const PORT = Number(process.env.PORT) || 3000;
const DATA_DIRECTORY = process.env.DATA_DIRECTORY || path.join(__dirname, 'data');
const DATABASE_PATH = path.join(DATA_DIRECTORY, 'database.json');
const SESSION_COOKIE = 'zombie_session';
const SESSION_DURATION_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_BODY_BYTES = 1024 * 1024;
const PASSWORD_KEY_LENGTH = 64;
const AUTH_WINDOW_MS = 15 * 60 * 1000;
const AUTH_REQUEST_LIMIT = 20;
const COOKIE_SECURE = process.env.COOKIE_SECURE === 'true';

let database;
let mutationQueue = Promise.resolve();
const authRequestCounts = new Map();

function createEmptyDatabase() {
    return {
        users: Object.create(null),
        saves: Object.create(null),
        sessions: Object.create(null)
    };
}

function asRecord(value) {
    return value && typeof value === 'object' && !Array.isArray(value)
        ? Object.assign(Object.create(null), value)
        : Object.create(null);
}

async function persistDatabase() {
    await fs.mkdir(DATA_DIRECTORY, { recursive: true });
    const temporaryPath = `${DATABASE_PATH}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
    await fs.writeFile(temporaryPath, JSON.stringify(database), { mode: 0o600 });
    await fs.rename(temporaryPath, DATABASE_PATH);
}

function mutateDatabase(operation) {
    const result = mutationQueue.then(operation);
    mutationQueue = result.catch(() => {});
    return result;
}

async function loadDatabase() {
    try {
        const stored = JSON.parse(await fs.readFile(DATABASE_PATH, 'utf8'));
        database = {
            users: asRecord(stored.users),
            saves: asRecord(stored.saves),
            sessions: asRecord(stored.sessions)
        };
    } catch (error) {
        if (error.code !== 'ENOENT') throw error;
        database = createEmptyDatabase();
        await persistDatabase();
    }
}

function sendJson(response, statusCode, body, extraHeaders = {}) {
    response.writeHead(statusCode, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        ...extraHeaders
    });
    response.end(JSON.stringify(body));
}

function sendError(response, statusCode, message, extraHeaders = {}) {
    sendJson(response, statusCode, { error: message }, extraHeaders);
}

async function readJson(request) {
    const chunks = [];
    let totalBytes = 0;
    for await (const chunk of request) {
        totalBytes += chunk.length;
        if (totalBytes > MAX_BODY_BYTES) {
            const error = new Error('请求内容过大');
            error.statusCode = 413;
            throw error;
        }
        chunks.push(chunk);
    }
    if (totalBytes === 0) return {};
    try {
        return JSON.parse(Buffer.concat(chunks).toString('utf8'));
    } catch (error) {
        const parseError = new Error('请求格式无效');
        parseError.statusCode = 400;
        throw parseError;
    }
}

function readCookie(request, name) {
    const cookieHeader = request.headers.cookie || '';
    for (const part of cookieHeader.split(';')) {
        const separator = part.indexOf('=');
        if (separator < 0) continue;
        if (part.slice(0, separator).trim() === name) {
            return decodeURIComponent(part.slice(separator + 1).trim());
        }
    }
    return null;
}

function sessionHash(token) {
    return createHash('sha256').update(token).digest('hex');
}

function cookieHeader(token, request) {
    const secure = request.socket.encrypted || COOKIE_SECURE ? '; Secure' : '';
    return `${SESSION_COOKIE}=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${SESSION_DURATION_MS / 1000}${secure}`;
}

function clearCookieHeader(request) {
    const secure = request.socket.encrypted || COOKIE_SECURE ? '; Secure' : '';
    return `${SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0${secure}`;
}

function getSession(request) {
    const token = readCookie(request, SESSION_COOKIE);
    if (!token) return null;
    const session = database.sessions[sessionHash(token)];
    if (!session || session.expiresAt <= Date.now()) return null;
    const account = database.users[session.username];
    if (!account) return null;
    return { token, session, account };
}

async function requireSession(request, response) {
    const currentSession = getSession(request);
    if (!currentSession) {
        sendError(response, 401, '请先登录');
        return null;
    }
    return currentSession;
}

function validUsername(username) {
    return typeof username === 'string' && /^[A-Za-z0-9_\u4e00-\u9fa5]{3,20}$/.test(username.trim());
}

function validPassword(password) {
    return typeof password === 'string' && password.length >= 8 && password.length <= 128;
}

function checkAuthRateLimit(request) {
    const clientAddress = request.socket.remoteAddress || 'unknown';
    const now = Date.now();
    let entry = authRequestCounts.get(clientAddress);
    if (!entry || entry.expiresAt <= now) {
        entry = { count: 0, expiresAt: now + AUTH_WINDOW_MS };
        authRequestCounts.set(clientAddress, entry);
    }
    if (entry.count >= AUTH_REQUEST_LIMIT) {
        return Math.max(1, Math.ceil((entry.expiresAt - now) / 1000));
    }
    entry.count++;
    return 0;
}

async function hashPassword(password, salt) {
    return scrypt(password, salt, PASSWORD_KEY_LENGTH, { N: 16384, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
}

async function createSession(username, request, response) {
    const token = randomBytes(32).toString('base64url');
    await mutateDatabase(async () => {
        const now = Date.now();
        for (const [hash, session] of Object.entries(database.sessions)) {
            if (!session || session.expiresAt <= now) delete database.sessions[hash];
        }
        database.sessions[sessionHash(token)] = {
            username,
            expiresAt: now + SESSION_DURATION_MS
        };
        await persistDatabase();
    });
    sendJson(response, 200, { user: { username: database.users[username].username } }, {
        'Set-Cookie': cookieHeader(token, request)
    });
}

function validSave(save) {
    if (!save || typeof save !== 'object' || Array.isArray(save) || save.version !== 1) return false;
    const numericFields = ['savedAt', 'score', 'health', 'maxHealth', 'ammo', 'maxAmmo', 'wave', 'zombiesInWave', 'zombiesKilled'];
    if (!numericFields.every(field => Number.isFinite(save[field]))) return false;
    if (!save.player || typeof save.player !== 'object' || !Array.isArray(save.zombies)) return false;
    return save.zombies.length <= 10000;
}

async function handleApi(request, response, url) {
    const origin = request.headers.origin;
    if (origin && new URL(origin).host !== request.headers.host) {
        sendError(response, 403, '请求来源不允许');
        return;
    }

    if (request.method === 'POST' && (url.pathname === '/api/register' || url.pathname === '/api/login')) {
        const retryAfter = checkAuthRateLimit(request);
        if (retryAfter) {
            sendError(response, 429, '操作过于频繁，请稍后再试', { 'Retry-After': String(retryAfter) });
            return;
        }
    }

    if (request.method === 'POST' && url.pathname === '/api/register') {
        const body = await readJson(request);
        const username = typeof body.username === 'string' ? body.username.trim() : '';
        const password = body.password;
        if (!validUsername(username)) {
            sendError(response, 400, '账号需为3-20位中文、字母、数字或下划线');
            return;
        }
        if (!validPassword(password)) {
            sendError(response, 400, '密码长度需为8-128位');
            return;
        }

        const accountKey = username.toLowerCase();
        const created = await mutateDatabase(async () => {
            if (Object.prototype.hasOwnProperty.call(database.users, accountKey)) return false;
            const salt = randomBytes(16);
            const passwordHash = await hashPassword(password, salt);
            database.users[accountKey] = {
                username,
                salt: salt.toString('hex'),
                passwordHash: passwordHash.toString('hex')
            };
            await persistDatabase();
            return true;
        });
        if (!created) {
            sendError(response, 409, '该账号已存在');
            return;
        }
        await createSession(accountKey, request, response);
        return;
    }

    if (request.method === 'POST' && url.pathname === '/api/login') {
        const body = await readJson(request);
        const username = typeof body.username === 'string' ? body.username.trim() : '';
        const password = body.password;
        if (!validUsername(username) || !validPassword(password)) {
            sendError(response, 401, '账号或密码不正确');
            return;
        }
        const accountKey = username.toLowerCase();
        const account = database.users[accountKey];
        if (!account) {
            sendError(response, 401, '账号或密码不正确');
            return;
        }
        const suppliedHash = await hashPassword(password, Buffer.from(account.salt, 'hex'));
        const storedHash = Buffer.from(account.passwordHash, 'hex');
        if (suppliedHash.length !== storedHash.length || !timingSafeEqual(suppliedHash, storedHash)) {
            sendError(response, 401, '账号或密码不正确');
            return;
        }
        await createSession(accountKey, request, response);
        return;
    }

    if (request.method === 'POST' && url.pathname === '/api/logout') {
        const currentSession = getSession(request);
        if (currentSession) {
            await mutateDatabase(async () => {
                delete database.sessions[sessionHash(currentSession.token)];
                await persistDatabase();
            });
        }
        sendJson(response, 200, { ok: true }, { 'Set-Cookie': clearCookieHeader(request) });
        return;
    }

    if (request.method === 'GET' && url.pathname === '/api/session') {
        const currentSession = await requireSession(request, response);
        if (currentSession) sendJson(response, 200, { user: { username: currentSession.account.username } });
        return;
    }

    if (url.pathname === '/api/save') {
        const currentSession = await requireSession(request, response);
        if (!currentSession) return;
        const username = currentSession.session.username;

        if (request.method === 'GET') {
            sendJson(response, 200, { save: database.saves[username] || null });
            return;
        }
        if (request.method === 'PUT') {
            const body = await readJson(request);
            if (!validSave(body.save)) {
                sendError(response, 400, '游戏存档数据无效');
                return;
            }
            await mutateDatabase(async () => {
                database.saves[username] = body.save;
                await persistDatabase();
            });
            sendJson(response, 200, { ok: true });
            return;
        }
        if (request.method === 'DELETE') {
            await mutateDatabase(async () => {
                delete database.saves[username];
                await persistDatabase();
            });
            sendJson(response, 200, { ok: true });
            return;
        }
    }

    sendError(response, 404, '接口不存在');
}

async function handleRequest(request, response) {
    try {
        const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
        if (url.pathname.startsWith('/api/')) {
            await handleApi(request, response, url);
            return;
        }
        if (request.method !== 'GET' && request.method !== 'HEAD') {
            sendError(response, 405, '请求方法不支持');
            return;
        }
        if (url.pathname !== '/' && url.pathname !== '/index.html') {
            sendError(response, 404, '页面不存在');
            return;
        }
        const html = await fs.readFile(path.join(__dirname, 'index.html'));
        response.writeHead(200, {
            'Content-Type': 'text/html; charset=utf-8',
            'Cache-Control': 'no-store',
            'X-Content-Type-Options': 'nosniff'
        });
        response.end(request.method === 'HEAD' ? undefined : html);
    } catch (error) {
        if (response.headersSent) {
            response.destroy();
            return;
        }
        if (error.statusCode) {
            sendError(response, error.statusCode, error.message);
            return;
        }
        console.error('请求处理失败:', error);
        sendError(response, 500, '服务器内部错误');
    }
}

async function startServer() {
    await loadDatabase();
    const server = http.createServer(handleRequest);
    server.listen(PORT, HOST, () => {
        console.log(`游戏服务已启动：http://${HOST}:${PORT}`);
        console.log(`账号与存档数据：${DATABASE_PATH}`);
    });
}

startServer().catch(error => {
    console.error('服务启动失败:', error);
    process.exitCode = 1;
});