// 会計管理ツール - Cloudflare Worker backend
// Provides account signup/login (session-token based) and CRUD APIs for
// businesses / accounts / entries, scoped to a "workspace" rather than a
// single user directly. Every user gets their own workspace at signup;
// other users can be invited (via a shareable invite link) to join that
// workspace so multiple accounts can manage the same accounting data
// together. Static frontend assets are served via the [assets] binding for
// any request that isn't under /api/.

const SESSION_TTL_DAYS = 30;
const PBKDF2_ITERATIONS = 100000;
const INVITE_TTL_DAYS = 7;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
  });
}
function errorResponse(message, status = 400) {
  return json({ error: message }, status);
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  return bytes;
}
function randomHex(numBytes) {
  const bytes = new Uint8Array(numBytes);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: hexToBytes(saltHex), iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    keyMaterial,
    256
  );
  return bytesToHex(new Uint8Array(bits));
}

function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/* ============ workspace helpers ============ */
async function createWorkspaceForUser(env, userId, name) {
  const res = await env.DB.prepare('INSERT INTO workspaces (name, owner_user_id) VALUES (?, ?)')
    .bind(name, userId).run();
  const workspaceId = res.meta.last_row_id;
  await env.DB.prepare('INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (?, ?, ?)')
    .bind(workspaceId, userId, 'owner').run();
  await env.DB.prepare('UPDATE users SET current_workspace_id = ? WHERE id = ?').bind(workspaceId, userId).run();
  return workspaceId;
}

// Resolves the authenticated user AND their active workspace + role in it.
// Falls back to a workspace the user owns if their stored current_workspace_id
// is missing or they're no longer a member of it (e.g. they were removed).
async function getUserFromRequest(request, env) {
  const auth = request.headers.get('Authorization') || '';
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  const token = m[1].trim();
  if (!token) return null;
  const row = await env.DB.prepare(
    `SELECT s.user_id as userId, s.expires_at as expiresAt, u.email as email, u.current_workspace_id as currentWorkspaceId
     FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token = ?`
  ).bind(token).first();
  if (!row) return null;
  if (new Date(row.expiresAt).getTime() < Date.now()) return null;

  let workspaceId = row.currentWorkspaceId;
  let role = null;
  if (workspaceId) {
    const member = await env.DB.prepare('SELECT role FROM workspace_members WHERE workspace_id = ? AND user_id = ?')
      .bind(workspaceId, row.userId).first();
    role = member ? member.role : null;
  }
  if (!role) {
    // Fall back to a workspace this user owns (created at signup, always kept).
    const owned = await env.DB.prepare(
      `SELECT wm.workspace_id as workspaceId, wm.role as role FROM workspace_members wm
       WHERE wm.user_id = ? ORDER BY (wm.role = 'owner') DESC, wm.workspace_id ASC LIMIT 1`
    ).bind(row.userId).first();
    if (owned) {
      workspaceId = owned.workspaceId;
      role = owned.role;
      await env.DB.prepare('UPDATE users SET current_workspace_id = ? WHERE id = ?').bind(workspaceId, row.userId).run();
    }
  }

  return { userId: row.userId, email: row.email, token, workspaceId: workspaceId || null, role };
}

function requireAuth(handler) {
  return async (request, env, ctx, params) => {
    const user = await getUserFromRequest(request, env);
    if (!user) return errorResponse('認証が必要です。再度ログインしてください。', 401);
    if (!user.workspaceId) return errorResponse('所属するワークスペースが見つかりません。', 409);
    return handler(request, env, ctx, params, user);
  };
}

async function readJson(request) {
  try {
    return await request.json();
  } catch (e) {
    return null;
  }
}

/* ============ mapping helpers (snake_case DB <-> camelCase API) ============ */
function bizToApi(row) {
  return {
    id: row.id,
    name: row.name,
    openingCash: row.opening_cash,
    entityType: row.entity_type,
    taxSettings: row.tax_settings ? JSON.parse(row.tax_settings) : null,
  };
}
function accToApi(row) {
  return {
    id: row.id,
    category: row.category,
    name: row.name,
    order: row.order_num,
    parentId: row.parent_id || null,
  };
}
function entryToApi(row) {
  return {
    id: row.id,
    businessId: row.business_id,
    accountId: row.account_id,
    month: row.month,
    kind: row.kind,
    amount: row.amount,
  };
}

/* ============ auth routes ============ */
async function handleSignup(request, env) {
  const body = await readJson(request);
  if (!body) return errorResponse('リクエストの形式が正しくありません。');
  const email = (body.email || '').trim().toLowerCase();
  const password = body.password || '';
  if (!isValidEmail(email)) return errorResponse('メールアドレスの形式が正しくありません。');
  if (password.length < 8) return errorResponse('パスワードは8文字以上で入力してください。');

  const existing = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
  if (existing) return errorResponse('このメールアドレスは既に登録されています。', 409);

  const salt = randomHex(16);
  const hash = await hashPassword(password, salt);
  const insert = await env.DB.prepare(
    'INSERT INTO users (email, password_hash, password_salt) VALUES (?, ?, ?)'
  ).bind(email, hash, salt).run();
  const userId = insert.meta.last_row_id;

  // Every user gets their own workspace to start in. If they were invited
  // (inviteToken provided), we still create this so they always have a
  // fallback home, then join+switch to the invited workspace right after.
  await createWorkspaceForUser(env, userId, `${email} のワークスペース`);

  const token = randomHex(32);
  const expiresAt = new Date(Date.now() + SESSION_TTL_DAYS * 86400000).toISOString();
  await env.DB.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)')
    .bind(token, userId, expiresAt).run();

  return json({ token, email });
}

async function handleLogin(request, env) {
  const body = await readJson(request);
  if (!body) return errorResponse('リクエストの形式が正しくありません。');
  const email = (body.email || '').trim().toLowerCase();
  const password = body.password || '';
  const user = await env.DB.prepare('SELECT id, email, password_hash, password_salt FROM users WHERE email = ?')
    .bind(email).first();
  if (!user) return errorResponse('メールアドレスまたはパスワードが正しくありません。', 401);
  const hash = await hashPassword(password, user.password_salt);
  if (hash !== user.password_hash) return errorResponse('メールアドレスまたはパスワードが正しくありません。', 401);

  const token = randomHex(32);
  const expiresAt = new Date(Date.now() + SESSION_TTL_DAYS * 86400000).toISOString();
  await env.DB.prepare('INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)')
    .bind(token, user.id, expiresAt).run();

  return json({ token, email: user.email });
}

const handleLogout = requireAuth(async (request, env, ctx, params, user) => {
  await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(user.token).run();
  return json({ ok: true });
});

const handleMe = requireAuth(async (request, env, ctx, params, user) => {
  return json({ email: user.email });
});

/* ============ bulk data ============ */
// A business with no rows in business_members is open to every workspace
// member. Once restricted (>=1 row), only the workspace owner and the
// assigned users can see it. This SQL fragment expresses that per business
// row; bind workspace_id then user_id (twice: once for businesses, once
// for entries' business subquery) as needed by the caller.
const VISIBLE_BUSINESS_SQL = `(
  NOT EXISTS (SELECT 1 FROM business_members bm WHERE bm.business_id = b.id)
  OR EXISTS (SELECT 1 FROM business_members bm WHERE bm.business_id = b.id AND bm.user_id = ?)
)`;

const handleGetData = requireAuth(async (request, env, ctx, params, user) => {
  const isOwner = user.role === 'owner';
  const [businesses, accounts, entries] = await Promise.all([
    isOwner
      ? env.DB.prepare('SELECT * FROM businesses WHERE workspace_id = ? ORDER BY id').bind(user.workspaceId).all()
      : env.DB.prepare(
          `SELECT b.* FROM businesses b WHERE b.workspace_id = ? AND ${VISIBLE_BUSINESS_SQL} ORDER BY b.id`
        ).bind(user.workspaceId, user.userId).all(),
    env.DB.prepare('SELECT * FROM accounts WHERE workspace_id = ? ORDER BY id').bind(user.workspaceId).all(),
    isOwner
      ? env.DB.prepare('SELECT * FROM entries WHERE workspace_id = ? ORDER BY id').bind(user.workspaceId).all()
      : env.DB.prepare(
          `SELECT e.* FROM entries e JOIN businesses b ON b.id = e.business_id
           WHERE e.workspace_id = ? AND ${VISIBLE_BUSINESS_SQL} ORDER BY e.id`
        ).bind(user.workspaceId, user.userId).all(),
  ]);
  return json({
    businesses: businesses.results.map(bizToApi),
    accounts: accounts.results.map(accToApi),
    entries: entries.results.map(entryToApi),
  });
});

/* ============ businesses ============ */
// Returns true if the given business is visible to this user: the workspace
// owner can always access every business; a non-owner member can access it
// only if the business is unrestricted (no business_members rows) or they're
// explicitly assigned to it.
async function canAccessBusiness(env, user, businessId) {
  if (user.role === 'owner') return true;
  const row = await env.DB.prepare(
    `SELECT 1 FROM businesses b WHERE b.id = ? AND b.workspace_id = ? AND ${VISIBLE_BUSINESS_SQL}`
  ).bind(businessId, user.workspaceId, user.userId).first();
  return !!row;
}

const handleCreateBusiness = requireAuth(async (request, env, ctx, params, user) => {
  const b = await readJson(request);
  if (!b || !b.name) return errorResponse('事業名が必要です。');
  const taxSettings = b.taxSettings ? JSON.stringify(b.taxSettings) : null;
  const res = await env.DB.prepare(
    'INSERT INTO businesses (workspace_id, name, opening_cash, entity_type, tax_settings) VALUES (?, ?, ?, ?, ?)'
  ).bind(user.workspaceId, b.name, b.openingCash || 0, b.entityType || 'individual', taxSettings).run();
  const row = await env.DB.prepare('SELECT * FROM businesses WHERE id = ?').bind(res.meta.last_row_id).first();
  return json(bizToApi(row));
});
const handleUpdateBusiness = requireAuth(async (request, env, ctx, params, user) => {
  const id = Number(params.id);
  const owned = await env.DB.prepare('SELECT id FROM businesses WHERE id = ? AND workspace_id = ?').bind(id, user.workspaceId).first();
  if (!owned) return errorResponse('対象の事業が見つかりません。', 404);
  if (!(await canAccessBusiness(env, user, id))) return errorResponse('この事業へのアクセス権がありません。', 403);
  const b = await readJson(request);
  if (!b) return errorResponse('リクエストの形式が正しくありません。');
  const taxSettings = b.taxSettings ? JSON.stringify(b.taxSettings) : null;
  await env.DB.prepare(
    'UPDATE businesses SET name = ?, opening_cash = ?, entity_type = ?, tax_settings = ? WHERE id = ? AND workspace_id = ?'
  ).bind(b.name, b.openingCash || 0, b.entityType || 'individual', taxSettings, id, user.workspaceId).run();
  const row = await env.DB.prepare('SELECT * FROM businesses WHERE id = ?').bind(id).first();
  return json(bizToApi(row));
});
const handleDeleteBusiness = requireAuth(async (request, env, ctx, params, user) => {
  const id = Number(params.id);
  if (!(await canAccessBusiness(env, user, id))) return errorResponse('この事業へのアクセス権がありません。', 403);
  await env.DB.prepare('DELETE FROM businesses WHERE id = ? AND workspace_id = ?').bind(id, user.workspaceId).run();
  return json({ ok: true });
});

/* ============ accounts ============ */
const handleCreateAccount = requireAuth(async (request, env, ctx, params, user) => {
  const a = await readJson(request);
  if (!a || !a.name || !a.category) return errorResponse('区分と科目名が必要です。');
  const res = await env.DB.prepare(
    'INSERT INTO accounts (workspace_id, category, name, order_num, parent_id) VALUES (?, ?, ?, ?, ?)'
  ).bind(user.workspaceId, a.category, a.name, a.order || 0, a.parentId || null).run();
  const row = await env.DB.prepare('SELECT * FROM accounts WHERE id = ?').bind(res.meta.last_row_id).first();
  return json(accToApi(row));
});
const handleUpdateAccount = requireAuth(async (request, env, ctx, params, user) => {
  const id = Number(params.id);
  const owned = await env.DB.prepare('SELECT id FROM accounts WHERE id = ? AND workspace_id = ?').bind(id, user.workspaceId).first();
  if (!owned) return errorResponse('対象の勘定科目が見つかりません。', 404);
  const a = await readJson(request);
  if (!a) return errorResponse('リクエストの形式が正しくありません。');
  await env.DB.prepare(
    'UPDATE accounts SET category = ?, name = ?, order_num = ?, parent_id = ? WHERE id = ? AND workspace_id = ?'
  ).bind(a.category, a.name, a.order || 0, a.parentId || null, id, user.workspaceId).run();
  const row = await env.DB.prepare('SELECT * FROM accounts WHERE id = ?').bind(id).first();
  return json(accToApi(row));
});
const handleDeleteAccount = requireAuth(async (request, env, ctx, params, user) => {
  const id = Number(params.id);
  await env.DB.prepare('DELETE FROM accounts WHERE id = ? AND workspace_id = ?').bind(id, user.workspaceId).run();
  return json({ ok: true });
});

/* ============ entries ============ */
const handleCreateEntry = requireAuth(async (request, env, ctx, params, user) => {
  const e = await readJson(request);
  if (!e || !e.businessId || !e.accountId || !e.month || !e.kind) {
    return errorResponse('必要な項目が不足しています。');
  }
  if (!(await canAccessBusiness(env, user, e.businessId))) return errorResponse('この事業へのアクセス権がありません。', 403);
  const res = await env.DB.prepare(
    'INSERT INTO entries (workspace_id, business_id, account_id, month, kind, amount) VALUES (?, ?, ?, ?, ?, ?)'
  ).bind(user.workspaceId, e.businessId, e.accountId, e.month, e.kind, e.amount || 0).run();
  const row = await env.DB.prepare('SELECT * FROM entries WHERE id = ?').bind(res.meta.last_row_id).first();
  return json(entryToApi(row));
});
const handleUpdateEntry = requireAuth(async (request, env, ctx, params, user) => {
  const id = Number(params.id);
  const owned = await env.DB.prepare('SELECT id, business_id FROM entries WHERE id = ? AND workspace_id = ?').bind(id, user.workspaceId).first();
  if (!owned) return errorResponse('対象のデータが見つかりません。', 404);
  if (!(await canAccessBusiness(env, user, owned.business_id))) return errorResponse('この事業へのアクセス権がありません。', 403);
  const e = await readJson(request);
  if (!e) return errorResponse('リクエストの形式が正しくありません。');
  if (!(await canAccessBusiness(env, user, e.businessId))) return errorResponse('この事業へのアクセス権がありません。', 403);
  await env.DB.prepare(
    'UPDATE entries SET business_id = ?, account_id = ?, month = ?, kind = ?, amount = ? WHERE id = ? AND workspace_id = ?'
  ).bind(e.businessId, e.accountId, e.month, e.kind, e.amount || 0, id, user.workspaceId).run();
  const row = await env.DB.prepare('SELECT * FROM entries WHERE id = ?').bind(id).first();
  return json(entryToApi(row));
});
const handleDeleteEntry = requireAuth(async (request, env, ctx, params, user) => {
  const id = Number(params.id);
  const owned = await env.DB.prepare('SELECT business_id FROM entries WHERE id = ? AND workspace_id = ?').bind(id, user.workspaceId).first();
  if (owned && !(await canAccessBusiness(env, user, owned.business_id))) return errorResponse('この事業へのアクセス権がありません。', 403);
  await env.DB.prepare('DELETE FROM entries WHERE id = ? AND workspace_id = ?').bind(id, user.workspaceId).run();
  return json({ ok: true });
});

/* ============ settings (tool name / logo) ============ */
const MAX_LOGO_DATA_URL_LENGTH = 400000; // ~300KB binary, generous for a small header logo

const handleGetSettings = requireAuth(async (request, env, ctx, params, user) => {
  const row = await env.DB.prepare('SELECT tool_name, logo_data_url FROM settings WHERE workspace_id = ?')
    .bind(user.workspaceId).first();
  return json({
    toolName: (row && row.tool_name) || null,
    logoDataUrl: (row && row.logo_data_url) || null,
  });
});
const handleUpdateSettings = requireAuth(async (request, env, ctx, params, user) => {
  const s = await readJson(request);
  if (!s) return errorResponse('リクエストの形式が正しくありません。');
  const toolName = typeof s.toolName === 'string' ? s.toolName.slice(0, 60) : null;
  const logoDataUrl = typeof s.logoDataUrl === 'string' ? s.logoDataUrl : null;
  if (logoDataUrl && logoDataUrl.length > MAX_LOGO_DATA_URL_LENGTH) {
    return errorResponse('ロゴ画像のサイズが大きすぎます。もう少し小さい画像を選んでください。');
  }
  await env.DB.prepare(
    `INSERT INTO settings (workspace_id, tool_name, logo_data_url) VALUES (?, ?, ?)
     ON CONFLICT(workspace_id) DO UPDATE SET tool_name = excluded.tool_name, logo_data_url = excluded.logo_data_url`
  ).bind(user.workspaceId, toolName, logoDataUrl).run();
  return json({ toolName, logoDataUrl });
});

/* ============ workspace / members / invites ============ */
const handleGetWorkspace = requireAuth(async (request, env, ctx, params, user) => {
  const ws = await env.DB.prepare('SELECT id, name FROM workspaces WHERE id = ?').bind(user.workspaceId).first();
  if (!ws) return errorResponse('ワークスペースが見つかりません。', 404);
  return json({ id: ws.id, name: ws.name, role: user.role });
});

const handleGetMembers = requireAuth(async (request, env, ctx, params, user) => {
  const rows = await env.DB.prepare(
    `SELECT u.id as userId, u.email as email, wm.role as role, wm.created_at as joinedAt
     FROM workspace_members wm JOIN users u ON u.id = wm.user_id
     WHERE wm.workspace_id = ? ORDER BY (wm.role = 'owner') DESC, wm.created_at ASC`
  ).bind(user.workspaceId).all();
  return json({ members: rows.results.map(r => ({ userId: r.userId, email: r.email, role: r.role, joinedAt: r.joinedAt })) });
});

/* ---- per-business member access (事業ごとのメンバー管理) ---- */
const handleGetBusinessMembers = requireAuth(async (request, env, ctx, params, user) => {
  const businessId = Number(params.id);
  const biz = await env.DB.prepare('SELECT id FROM businesses WHERE id = ? AND workspace_id = ?')
    .bind(businessId, user.workspaceId).first();
  if (!biz) return errorResponse('対象の事業が見つかりません。', 404);
  const assigned = await env.DB.prepare('SELECT user_id as userId FROM business_members WHERE business_id = ?')
    .bind(businessId).all();
  const assignedUserIds = assigned.results.map(r => r.userId);
  return json({ businessId, restricted: assignedUserIds.length > 0, assignedUserIds });
});

const handleUpdateBusinessMembers = requireAuth(async (request, env, ctx, params, user) => {
  if (user.role !== 'owner') return errorResponse('事業のメンバー設定はオーナーのみ行えます。', 403);
  const businessId = Number(params.id);
  const biz = await env.DB.prepare('SELECT id FROM businesses WHERE id = ? AND workspace_id = ?')
    .bind(businessId, user.workspaceId).first();
  if (!biz) return errorResponse('対象の事業が見つかりません。', 404);
  const body = await readJson(request);
  if (!body || !Array.isArray(body.userIds)) return errorResponse('リクエストの形式が正しくありません。');
  // Only workspace members may be assigned; silently drop anything else.
  const validMembers = await env.DB.prepare('SELECT user_id as userId FROM workspace_members WHERE workspace_id = ?')
    .bind(user.workspaceId).all();
  const validIds = new Set(validMembers.results.map(r => r.userId));
  const userIds = Array.from(new Set(body.userIds.map(Number).filter(id => validIds.has(id))));

  const stmts = [env.DB.prepare('DELETE FROM business_members WHERE business_id = ?').bind(businessId)];
  for (const uid of userIds) {
    stmts.push(env.DB.prepare('INSERT INTO business_members (business_id, user_id) VALUES (?, ?)').bind(businessId, uid));
  }
  await env.DB.batch(stmts);
  return json({ businessId, restricted: userIds.length > 0, assignedUserIds: userIds });
});

const handleRemoveMember = requireAuth(async (request, env, ctx, params, user) => {
  if (user.role !== 'owner') return errorResponse('メンバーの削除はオーナーのみ行えます。', 403);
  const targetUserId = Number(params.id);
  if (targetUserId === user.userId) return errorResponse('自分自身を削除することはできません。');
  const target = await env.DB.prepare('SELECT role FROM workspace_members WHERE workspace_id = ? AND user_id = ?')
    .bind(user.workspaceId, targetUserId).first();
  if (!target) return errorResponse('対象のメンバーが見つかりません。', 404);
  await env.DB.prepare('DELETE FROM workspace_members WHERE workspace_id = ? AND user_id = ?')
    .bind(user.workspaceId, targetUserId).run();
  // Also drop any per-business access assignments this user had within this workspace.
  await env.DB.prepare(
    `DELETE FROM business_members WHERE user_id = ? AND business_id IN (SELECT id FROM businesses WHERE workspace_id = ?)`
  ).bind(targetUserId, user.workspaceId).run();
  // If the removed member's active workspace was this one, bump them back to
  // a workspace they own so they aren't left pointing at data they can't see.
  const fallback = await env.DB.prepare(
    `SELECT workspace_id as workspaceId FROM workspace_members WHERE user_id = ? AND role = 'owner' LIMIT 1`
  ).bind(targetUserId).first();
  if (fallback) {
    await env.DB.prepare('UPDATE users SET current_workspace_id = ? WHERE id = ? AND current_workspace_id = ?')
      .bind(fallback.workspaceId, targetUserId, user.workspaceId).run();
  }
  return json({ ok: true });
});

const handleCreateInvite = requireAuth(async (request, env, ctx, params, user) => {
  const token = randomHex(20);
  const expiresAt = new Date(Date.now() + INVITE_TTL_DAYS * 86400000).toISOString();
  await env.DB.prepare('INSERT INTO invites (token, workspace_id, created_by, expires_at) VALUES (?, ?, ?, ?)')
    .bind(token, user.workspaceId, user.userId, expiresAt).run();
  return json({ token, expiresAt });
});

const handleListInvites = requireAuth(async (request, env, ctx, params, user) => {
  const rows = await env.DB.prepare(
    `SELECT i.token as token, i.created_at as createdAt, i.expires_at as expiresAt, i.accepted_at as acceptedAt, u.email as acceptedByEmail
     FROM invites i LEFT JOIN users u ON u.id = i.accepted_by
     WHERE i.workspace_id = ? ORDER BY i.created_at DESC LIMIT 50`
  ).bind(user.workspaceId).all();
  return json({
    invites: rows.results.map(r => ({
      token: r.token,
      createdAt: r.createdAt,
      expiresAt: r.expiresAt,
      acceptedAt: r.acceptedAt || null,
      acceptedByEmail: r.acceptedByEmail || null,
      expired: new Date(r.expiresAt).getTime() < Date.now(),
    })),
  });
});

// Accepting an invite requires being logged in (as either a brand-new or
// existing account) — the frontend handles signing up/logging in first,
// then calls this so the invited user joins and switches into the shared workspace.
const handleAcceptInvite = requireAuth(async (request, env, ctx, params, user) => {
  const token = params.id;
  const invite = await env.DB.prepare('SELECT * FROM invites WHERE token = ?').bind(token).first();
  if (!invite) return errorResponse('招待リンクが見つかりません。すでに無効になっている可能性があります。', 404);
  if (invite.accepted_at) return errorResponse('この招待リンクはすでに使用されています。', 409);
  if (new Date(invite.expires_at).getTime() < Date.now()) return errorResponse('この招待リンクの有効期限が切れています。', 410);

  const already = await env.DB.prepare('SELECT 1 FROM workspace_members WHERE workspace_id = ? AND user_id = ?')
    .bind(invite.workspace_id, user.userId).first();
  if (!already) {
    await env.DB.prepare('INSERT INTO workspace_members (workspace_id, user_id, role) VALUES (?, ?, ?)')
      .bind(invite.workspace_id, user.userId, 'member').run();
  }
  await env.DB.prepare('UPDATE invites SET accepted_by = ?, accepted_at = datetime(\'now\') WHERE token = ?')
    .bind(user.userId, token).run();
  await env.DB.prepare('UPDATE users SET current_workspace_id = ? WHERE id = ?')
    .bind(invite.workspace_id, user.userId).run();

  const ws = await env.DB.prepare('SELECT name FROM workspaces WHERE id = ?').bind(invite.workspace_id).first();
  return json({ ok: true, workspaceId: invite.workspace_id, workspaceName: ws ? ws.name : null });
});

/* ============ danger zone: wipe all of the current workspace's data ============ */
const handleClearAll = requireAuth(async (request, env, ctx, params, user) => {
  await env.DB.batch([
    env.DB.prepare('DELETE FROM entries WHERE workspace_id = ?').bind(user.workspaceId),
    env.DB.prepare('DELETE FROM accounts WHERE workspace_id = ?').bind(user.workspaceId),
    env.DB.prepare('DELETE FROM businesses WHERE workspace_id = ?').bind(user.workspaceId),
  ]);
  return json({ ok: true });
});

/* ============ router ============ */
const ROUTES = [
  ['POST', /^\/api\/auth\/signup$/, (req, env) => handleSignup(req, env)],
  ['POST', /^\/api\/auth\/login$/, (req, env) => handleLogin(req, env)],
  ['POST', /^\/api\/auth\/logout$/, handleLogout],
  ['GET', /^\/api\/auth\/me$/, handleMe],
  ['GET', /^\/api\/data$/, handleGetData],
  ['POST', /^\/api\/data\/clear$/, handleClearAll],

  ['GET', /^\/api\/settings$/, handleGetSettings],
  ['PUT', /^\/api\/settings$/, handleUpdateSettings],

  ['GET', /^\/api\/workspace$/, handleGetWorkspace],
  ['GET', /^\/api\/workspace\/members$/, handleGetMembers],
  ['DELETE', /^\/api\/workspace\/members\/(\d+)$/, handleRemoveMember],
  ['POST', /^\/api\/invites$/, handleCreateInvite],
  ['GET', /^\/api\/invites$/, handleListInvites],
  ['POST', /^\/api\/invites\/([a-f0-9]+)\/accept$/, handleAcceptInvite],

  ['POST', /^\/api\/businesses$/, handleCreateBusiness],
  ['PUT', /^\/api\/businesses\/(\d+)$/, handleUpdateBusiness],
  ['DELETE', /^\/api\/businesses\/(\d+)$/, handleDeleteBusiness],
  ['GET', /^\/api\/businesses\/(\d+)\/members$/, handleGetBusinessMembers],
  ['PUT', /^\/api\/businesses\/(\d+)\/members$/, handleUpdateBusinessMembers],

  ['POST', /^\/api\/accounts$/, handleCreateAccount],
  ['PUT', /^\/api\/accounts\/(\d+)$/, handleUpdateAccount],
  ['DELETE', /^\/api\/accounts\/(\d+)$/, handleDeleteAccount],

  ['POST', /^\/api\/entries$/, handleCreateEntry],
  ['PUT', /^\/api\/entries\/(\d+)$/, handleUpdateEntry],
  ['DELETE', /^\/api\/entries\/(\d+)$/, handleDeleteEntry],
];

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const pathname = url.pathname;

    if (pathname.startsWith('/api/')) {
      for (const [method, pattern, handler] of ROUTES) {
        if (request.method !== method) continue;
        const m = pathname.match(pattern);
        if (!m) continue;
        try {
          return await handler(request, env, ctx, { id: m[1] });
        } catch (err) {
          return errorResponse('サーバーエラーが発生しました: ' + (err && err.message ? err.message : String(err)), 500);
        }
      }
      return errorResponse('Not found', 404);
    }

    // Everything else: serve the static frontend
    return env.ASSETS.fetch(request);
  },
};
