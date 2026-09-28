const http = require('node:http');
const fs = require('node:fs/promises');
const path = require('node:path');
const { promisify } = require('node:util');
const { randomBytes, scrypt: scryptCallback, timingSafeEqual, createHash } = require('node:crypto');

const scrypt = promisify(scryptCallback);
const HOST = process.env.HOST || '0.0.0.0';
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
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || '';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';

let database;
let mutationQueue = Promise.resolve();
const authRequestCounts = new Map();
const coopRooms = new Map();
const COOP_ROOM_IDLE_MS = 10 * 60 * 1000;
const COOP_HOST_TIMEOUT_MS = 12000;
const COOP_ROOM_PLAYER_LIMIT = 4;

function createEmptyDatabase() {
    return {
        users: Object.create(null),
        saves: Object.create(null),
        sessions: Object.create(null),
        friendships: Object.create(null)
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
            sessions: asRecord(stored.sessions),
            friendships: asRecord(stored.friendships)
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

function normalizeRecoveryName(name) {
    return typeof name === 'string' ? name.trim().normalize('NFKC').toLowerCase() : '';
}

function validRecoveryName(name) {
    const normalized = normalizeRecoveryName(name);
    return normalized.length >= 1 && normalized.length <= 64 && !/[\u0000-\u001f\u007f]/.test(normalized);
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

async function ensureAdminAccount() {
    if (!ADMIN_USERNAME && !ADMIN_PASSWORD) return;
    if (!validUsername(ADMIN_USERNAME) || !validPassword(ADMIN_PASSWORD)) {
        throw new Error('管理员引导配置无效：需设置有效的 ADMIN_USERNAME 和至少8位 ADMIN_PASSWORD');
    }

    const username = ADMIN_USERNAME.trim();
    const accountKey = username.toLowerCase();
    await mutateDatabase(async () => {
        const existing = database.users[accountKey];
        if (existing) {
            if (existing.role !== 'admin') {
                throw new Error('管理员账号名已被普通账号占用，请设置一个未注册的 ADMIN_USERNAME');
            }
            return;
        }

        const salt = randomBytes(16);
        const passwordHash = await hashPassword(ADMIN_PASSWORD, salt);
        database.users[accountKey] = {
            username,
            salt: salt.toString('hex'),
            passwordHash: passwordHash.toString('hex'),
            role: 'admin'
        };
        await persistDatabase();
    });
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
    sendJson(response, 200, {
        user: {
            username: database.users[username].username,
            recoveryReady: Boolean(database.users[username].recoveryNameHash),
            isAdmin: database.users[username].role === 'admin'
        }
    }, {
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

function getFriendshipState(username) {
    const stored = database.friendships[username];
    const state = stored && typeof stored === 'object' && !Array.isArray(stored) ? stored : {};
    state.friends = Array.isArray(state.friends) ? state.friends : [];
    state.incoming = Array.isArray(state.incoming) ? state.incoming : [];
    state.outgoing = Array.isArray(state.outgoing) ? state.outgoing : [];
    database.friendships[username] = state;
    return state;
}

function friendNames(usernames) {
    return usernames
        .map(username => database.users[username]?.username)
        .filter(Boolean);
}

function removeUsername(usernames, username) {
    let index;
    while ((index = usernames.indexOf(username)) !== -1) usernames.splice(index, 1);
}

function cleanCoopRooms() {
    const now = Date.now();
    for (const [code, room] of coopRooms) {
        if (now - room.lastActiveAt > COOP_ROOM_IDLE_MS || now - room.hostLastActiveAt > COOP_HOST_TIMEOUT_MS) {
            coopRooms.delete(code);
        }
    }
}

function createCoopRoom(host, invitedUsers) {
    cleanCoopRooms();
    let code;
    do {
        code = randomBytes(6).toString('hex').toUpperCase();
    } while (coopRooms.has(code));
    const room = {
        code,
        host,
        members: new Set([host]),
        invited: new Set(invitedUsers),
        players: new Map(),
        shots: [],
        state: null,
        lastActiveAt: Date.now(),
        hostLastActiveAt: Date.now()
    };
    coopRooms.set(code, room);
    return room;
}

async function handleApi(request, response, url) {
    const origin = request.headers.origin;
    if (origin && new URL(origin).host !== request.headers.host) {
        sendError(response, 403, '请求来源不允许');
        return;
    }

    if (request.method === 'POST' && ['/api/register', '/api/login', '/api/reset-password'].includes(url.pathname)) {
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
        const recoveryName = body.recoveryName;
        if (!validUsername(username)) {
            sendError(response, 400, '账号需为3-20位中文、字母、数字或下划线');
            return;
        }
        if (!validPassword(password)) {
            sendError(response, 400, '密码长度需为8-128位');
            return;
        }
        if (!validRecoveryName(recoveryName)) {
            sendError(response, 400, '请输入有效的好友名称（1-64位）');
            return;
        }

        const accountKey = username.toLowerCase();
        const created = await mutateDatabase(async () => {
            if (Object.prototype.hasOwnProperty.call(database.users, accountKey)) return false;
            const salt = randomBytes(16);
            const passwordHash = await hashPassword(password, salt);
            const recoveryNameSalt = randomBytes(16);
            const recoveryNameHash = await hashPassword(normalizeRecoveryName(recoveryName), recoveryNameSalt);
            database.users[accountKey] = {
                username,
                salt: salt.toString('hex'),
                passwordHash: passwordHash.toString('hex'),
                recoveryNameSalt: recoveryNameSalt.toString('hex'),
                recoveryNameHash: recoveryNameHash.toString('hex'),
                role: 'player'
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

    if (request.method === 'POST' && url.pathname === '/api/reset-password') {
        const body = await readJson(request);
        const username = typeof body.username === 'string' ? body.username.trim() : '';
        const recoveryName = body.recoveryName;
        const newPassword = body.newPassword;
        const accountKey = username.toLowerCase();
        const account = validUsername(username) ? database.users[accountKey] : null;
        if (!account || !account.recoveryNameSalt || !account.recoveryNameHash ||
            !validRecoveryName(recoveryName) || !validPassword(newPassword)) {
            sendError(response, 400, '账号、好友名称或新密码不正确');
            return;
        }

        const suppliedHash = await hashPassword(
            normalizeRecoveryName(recoveryName),
            Buffer.from(account.recoveryNameSalt, 'hex')
        );
        const storedHash = Buffer.from(account.recoveryNameHash, 'hex');
        if (suppliedHash.length !== storedHash.length || !timingSafeEqual(suppliedHash, storedHash)) {
            sendError(response, 400, '账号、好友名称或新密码不正确');
            return;
        }

        const passwordSalt = randomBytes(16);
        const passwordHash = await hashPassword(newPassword, passwordSalt);
        await mutateDatabase(async () => {
            database.users[accountKey].salt = passwordSalt.toString('hex');
            database.users[accountKey].passwordHash = passwordHash.toString('hex');
            for (const [hash, session] of Object.entries(database.sessions)) {
                if (session?.username === accountKey) delete database.sessions[hash];
            }
            await persistDatabase();
        });
        sendJson(response, 200, { ok: true });
        return;
    }

    if (request.method === 'POST' && url.pathname === '/api/recovery-name') {
        const currentSession = await requireSession(request, response);
        if (!currentSession) return;
        const body = await readJson(request);
        if (!validRecoveryName(body.recoveryName)) {
            sendError(response, 400, '请输入有效的好友名称（1-64位）');
            return;
        }
        const recoveryNameSalt = randomBytes(16);
        const recoveryNameHash = await hashPassword(
            normalizeRecoveryName(body.recoveryName),
            recoveryNameSalt
        );
        await mutateDatabase(async () => {
            const account = database.users[currentSession.session.username];
            account.recoveryNameSalt = recoveryNameSalt.toString('hex');
            account.recoveryNameHash = recoveryNameHash.toString('hex');
            await persistDatabase();
        });
        sendJson(response, 200, { ok: true });
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
        if (currentSession) sendJson(response, 200, {
            user: {
                username: currentSession.account.username,
                recoveryReady: Boolean(currentSession.account.recoveryNameHash),
                isAdmin: currentSession.account.role === 'admin'
            }
        });
        return;
    }

    if (url.pathname.startsWith('/api/admin/')) {
        const currentSession = await requireSession(request, response);
        if (!currentSession) return;
        if (currentSession.account.role !== 'admin') {
            sendError(response, 403, '需要管理员权限');
            return;
        }

        if (request.method === 'GET' && url.pathname === '/api/admin/users') {
            const users = Object.values(database.users)
                .map(account => ({
                    username: account.username,
                    role: account.role === 'admin' ? 'admin' : 'player'
                }))
                .sort((left, right) => left.username.localeCompare(right.username, 'zh-CN'));
            sendJson(response, 200, { users });
            return;
        }

        const deleteMatch = request.method === 'DELETE'
            ? url.pathname.match(/^\/api\/admin\/users\/([^/]+)$/)
            : null;
        if (!deleteMatch) {
            sendError(response, 404, '管理员接口不存在');
            return;
        }

        let targetName;
        try {
            targetName = decodeURIComponent(deleteMatch[1]).trim();
        } catch (error) {
            sendError(response, 400, '账号格式无效');
            return;
        }
        if (!validUsername(targetName)) {
            sendError(response, 400, '账号格式无效');
            return;
        }
        const target = targetName.toLowerCase();
        if (target === currentSession.session.username) {
            sendError(response, 400, '不能删除当前管理员账号');
            return;
        }
        const targetAccount = database.users[target];
        if (!targetAccount) {
            sendError(response, 404, '账号不存在');
            return;
        }
        if (targetAccount.role === 'admin') {
            sendError(response, 403, '不能删除其他管理员账号');
            return;
        }

        await mutateDatabase(async () => {
            delete database.users[target];
            delete database.saves[target];
            delete database.friendships[target];
            for (const [hash, session] of Object.entries(database.sessions)) {
                if (session?.username === target) delete database.sessions[hash];
            }
            for (const friendship of Object.values(database.friendships)) {
                for (const field of ['friends', 'incoming', 'outgoing']) {
                    if (Array.isArray(friendship[field])) removeUsername(friendship[field], target);
                }
            }
            await persistDatabase();
        });
        for (const [code, room] of coopRooms) {
            if (room.host === target) {
                coopRooms.delete(code);
                continue;
            }
            room.members.delete(target);
            room.invited.delete(target);
            room.players.delete(target);
            room.shots = room.shots.filter(shot => shot.owner !== target);
        }
        sendJson(response, 200, { ok: true });
        return;
    }

    if (url.pathname.startsWith('/api/friends')) {
        const currentSession = await requireSession(request, response);
        if (!currentSession) return;
        const username = currentSession.session.username;
        const state = getFriendshipState(username);

        if (request.method === 'GET' && url.pathname === '/api/friends') {
            sendJson(response, 200, {
                friends: friendNames(state.friends),
                incoming: friendNames(state.incoming),
                outgoing: friendNames(state.outgoing)
            });
            return;
        }

        if (request.method === 'GET' && url.pathname === '/api/friends/search') {
            const targetName = (url.searchParams.get('username') || '').trim();
            if (!validUsername(targetName)) {
                sendError(response, 400, '账号格式无效');
                return;
            }
            const target = targetName.toLowerCase();
            const account = database.users[target];
            if (!account) {
                sendJson(response, 200, { found: false });
                return;
            }
            const other = getFriendshipState(target);
            let relationship = 'available';
            if (target === username) relationship = 'self';
            else if (state.friends.includes(target)) relationship = 'friend';
            else if (state.incoming.includes(target)) relationship = 'incoming';
            else if (state.outgoing.includes(target)) relationship = 'outgoing';
            sendJson(response, 200, {
                found: true,
                username: account.username,
                relationship
            });
            return;
        }

        const actions = {
            '/api/friends/request': 'request',
            '/api/friends/accept': 'accept',
            '/api/friends/reject': 'reject',
            '/api/friends/cancel': 'cancel',
            '/api/friends/remove': 'remove'
        };
        const action = actions[url.pathname];
        if (request.method !== 'POST' || !action) {
            sendError(response, 404, '接口不存在');
            return;
        }

        const body = await readJson(request);
        const targetName = typeof body.username === 'string' ? body.username.trim() : '';
        if (!validUsername(targetName)) {
            sendError(response, 400, '账号格式无效');
            return;
        }
        const target = targetName.toLowerCase();
        if (!database.users[target]) {
            sendError(response, 404, '未找到该账号');
            return;
        }
        if (target === username) {
            sendError(response, 400, '不能添加自己为好友');
            return;
        }

        await mutateDatabase(async () => {
            const current = getFriendshipState(username);
            const other = getFriendshipState(target);
            if (action === 'request') {
                if (current.friends.includes(target)) throw Object.assign(new Error('对方已经是你的好友'), { statusCode: 409 });
                if (current.outgoing.includes(target)) throw Object.assign(new Error('好友请求已发送'), { statusCode: 409 });
                if (current.incoming.includes(target)) throw Object.assign(new Error('对方已向你发送请求，请在待处理列表中通过'), { statusCode: 409 });
                current.outgoing.push(target);
                other.incoming.push(username);
            } else if (action === 'accept' || action === 'reject') {
                if (!current.incoming.includes(target)) throw Object.assign(new Error('没有该好友请求'), { statusCode: 404 });
                removeUsername(current.incoming, target);
                removeUsername(other.outgoing, username);
                if (action === 'accept') {
                    if (!current.friends.includes(target)) current.friends.push(target);
                    if (!other.friends.includes(username)) other.friends.push(username);
                }
            } else if (action === 'cancel') {
                if (!current.outgoing.includes(target)) throw Object.assign(new Error('没有待撤回的好友请求'), { statusCode: 404 });
                removeUsername(current.outgoing, target);
                removeUsername(other.incoming, username);
            } else {
                if (!current.friends.includes(target)) throw Object.assign(new Error('对方不在好友列表中'), { statusCode: 404 });
                removeUsername(current.friends, target);
                removeUsername(other.friends, username);
            }
            await persistDatabase();
        });
        sendJson(response, 200, { ok: true });
        return;
    }

    if (url.pathname.startsWith('/api/coop/')) {
        const currentSession = await requireSession(request, response);
        if (!currentSession) return;
        const username = currentSession.session.username;

        if (request.method === 'GET' && url.pathname === '/api/coop/invitations') {
            cleanCoopRooms();
            const invitations = [];
            for (const room of coopRooms.values()) {
                if (room.invited.has(username) && !room.members.has(username)) {
                    invitations.push({
                        code: room.code,
                        host: database.users[room.host]?.username || room.host,
                        players: room.members.size
                    });
                }
            }
            sendJson(response, 200, { invitations });
            return;
        }

        if (request.method === 'POST' && url.pathname === '/api/coop/rooms') {
            const body = await readJson(request);
            const invitedNames = Array.isArray(body.usernames)
                ? body.usernames.map(name => typeof name === 'string' ? name.trim() : '')
                : [typeof body.username === 'string' ? body.username.trim() : ''];
            if (invitedNames.length < 1 || invitedNames.length > COOP_ROOM_PLAYER_LIMIT - 1 ||
                !invitedNames.every(validUsername)) {
                sendError(response, 400, '好友账号格式无效');
                return;
            }
            const invitedUsers = [...new Set(invitedNames.map(name => name.toLowerCase()))];
            const friendship = getFriendshipState(username);
            if (invitedUsers.some(invited => !friendship.friends.includes(invited))) {
                sendError(response, 403, '只能邀请好友加入房间');
                return;
            }
            const room = createCoopRoom(username, invitedUsers);
            sendJson(response, 201, { code: room.code, slot: 0 });
            return;
        }

        const roomMatch = url.pathname.match(/^\/api\/coop\/rooms\/([A-F0-9]{12})\/(join|sync|leave)$/);
        if (!roomMatch || request.method !== 'POST') {
            sendError(response, 404, '联机接口不存在');
            return;
        }
        const [, code, action] = roomMatch;
        cleanCoopRooms();
        const room = coopRooms.get(code);
        if (!room) {
            sendError(response, 404, '房间不存在或已过期');
            return;
        }

        if (action === 'join') {
            if (!room.invited.has(username) && !room.members.has(username)) {
                sendError(response, 403, '此房间仅限受邀好友加入');
                return;
            }
            if (!room.members.has(username) && room.members.size >= COOP_ROOM_PLAYER_LIMIT) {
                sendError(response, 409, '房间已满');
                return;
            }
            room.members.add(username);
            room.lastActiveAt = Date.now();
            sendJson(response, 200, {
                code,
                slot: Array.from(room.members).indexOf(username),
                host: database.users[room.host]?.username || room.host,
                state: room.state
            });
            return;
        }

        if (!room.members.has(username)) {
            sendError(response, 403, '你不在此房间中');
            return;
        }
        if (action === 'leave') {
            if (username === room.host) {
                coopRooms.delete(code);
            } else {
                room.members.delete(username);
                room.players.delete(username);
                room.lastActiveAt = Date.now();
            }
            sendJson(response, 200, { ok: true });
            return;
        }

        const body = await readJson(request);
        const input = body.input;
        if (!input || !Number.isFinite(input.x) || !Number.isFinite(input.y) ||
            !Number.isFinite(input.aimX) || !Number.isFinite(input.aimY)) {
            sendError(response, 400, '玩家状态无效');
            return;
        }
        const account = database.users[username];
        room.players.set(username, {
            id: username,
            username: account.username,
            slot: Array.from(room.members).indexOf(username),
            x: Math.max(-10000, Math.min(10000, input.x)),
            y: Math.max(-10000, Math.min(10000, input.y)),
            aimX: Math.max(-10000, Math.min(10000, input.aimX)),
            aimY: Math.max(-10000, Math.min(10000, input.aimY)),
            color: typeof input.color === 'string' && /^#[0-9a-f]{6}$/i.test(input.color) ? input.color : '#3498db',
            invincible: Boolean(input.invincible),
            health: Math.max(0, Math.min(100000, Number.isFinite(input.health) ? input.health : 100)),
            maxHealth: Math.max(1, Math.min(100000, Number.isFinite(input.maxHealth) ? input.maxHealth : 100)),
            ammo: Math.max(0, Math.min(100000, Number.isFinite(input.ammo) ? input.ammo : 0)),
            maxAmmo: Math.max(1, Math.min(100000, Number.isFinite(input.maxAmmo) ? input.maxAmmo : 30)),
            sniperAmmo: Math.max(0, Math.min(100000, Number.isFinite(input.sniperAmmo) ? input.sniperAmmo : 0)),
            sniperMaxAmmo: Math.max(1, Math.min(100000, Number.isFinite(input.sniperMaxAmmo) ? input.sniperMaxAmmo : 5)),
            weapon: typeof input.weapon === 'string' ? input.weapon.slice(0, 24) : '手枪',
            score: Math.max(0, Math.min(1e12, Number.isFinite(input.score) ? input.score : 0)),
            wave: Math.max(1, Math.min(99999, Number.isFinite(input.wave) ? input.wave : 1)),
            updatedAt: Date.now()
        });
        if (username === room.host) room.hostLastActiveAt = Date.now();
        if (username === room.host && body.state && typeof body.state === 'object' && !Array.isArray(body.state)) {
            room.state = body.state;
        }
        if (Array.isArray(input.shots)) {
            for (const shot of input.shots.slice(0, 12)) {
                const fields = ['x', 'y', 'velocityX', 'velocityY', 'radius', 'damage'];
                if (!fields.every(field => Number.isFinite(shot[field]))) continue;
                room.shots.push({
                    x: shot.x,
                    y: shot.y,
                    velocityX: shot.velocityX,
                    velocityY: shot.velocityY,
                    radius: Math.max(1, Math.min(12, shot.radius)),
                    damage: Math.max(1, Math.min(500, shot.damage)),
                    color: shot.isSniper ? '#00ff00' : '#f1c40f',
                    isSniper: Boolean(shot.isSniper),
                    owner: username
                });
            }
        }
        room.lastActiveAt = Date.now();
        const players = Array.from(room.players.values())
            .filter(player => room.members.has(player.id) && Date.now() - player.updatedAt < 5000);
        const shots = username === room.host ? room.shots.splice(0) : [];
        sendJson(response, 200, { state: room.state, players, shots, host: room.host });
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
    await ensureAdminAccount();
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