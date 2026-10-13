require('dotenv').config();
const express = require('express'), cookie = require('cookie-parser'), jwt = require('jsonwebtoken'), { Pool } = require('pg');
const E = process.env, db = new Pool({ connectionString: E.DATABASE_URL });
const app = express(); app.use(express.json()); app.use(cookie());
const DISCORD = 'https://discord.com/api/v10';
const q = (s, p) => db.query(s, p).then(r => r.rows);
const audit = (u, action, entity, id, before, after, req) =>
  q('INSERT INTO audit_logs(actor_id,action,entity,entity_id,before,after,ip) VALUES($1,$2,$3,$4,$5,$6,$7)',
    [u?.id ?? null, action, entity, String(id ?? ''), before ?? null, after ?? null, req?.ip ?? null]);

// ---------- Auth ----------
const sign = u => jwt.sign({ id: u.id }, E.JWT_SECRET, { expiresIn: '12h' });
const setCookie = (res, u) => res.cookie('t', sign(u), { httpOnly: true, sameSite: 'lax', secure: E.BASE_URL?.startsWith('https') });
async function loadUser(req, res, next) {
  try {
    const { id } = jwt.verify(req.cookies.t || '', E.JWT_SECRET);
    const [u] = await q('SELECT * FROM web_users WHERE id=$1 AND status=\'active\'', [id]);
    if (!u) throw 0; req.user = u; u.perms = await getPerms(u); next();
  } catch { res.status(401).json({ error: 'غير مسجّل الدخول' }); }
}
async function getPerms(u) {
  const all = (await q('SELECT key FROM permissions')).map(r => r.key);
  if (u.is_owner) return new Set(all);
  const s = new Set((await q(`SELECT DISTINCT rp.permission_key k FROM staff_profiles sp
    JOIN staff_role_assignments a ON a.profile_id=sp.id AND a.ended_at IS NULL
    JOIN role_permissions rp ON rp.staff_role_id=a.staff_role_id WHERE sp.discord_user_id=$1`, [u.discord_user_id])).map(r => r.k));
  for (const r of await q('SELECT permission_key k, effect e FROM user_permissions WHERE web_user_id=$1', [u.id]))
    r.e === 'allow' ? s.add(r.k) : s.delete(r.k);
  return s;
}
const need = k => (req, res, next) => req.user.perms.has(k) ? next() : res.status(403).json({ error: 'لا تملك الصلاحية: ' + k });

app.get('/auth/login', (req, res) => {
  if (!E.DISCORD_CLIENT_ID) return res.status(500).send('لم يتم إعداد Discord OAuth');
  res.redirect(`${DISCORD}/oauth2/authorize?client_id=${E.DISCORD_CLIENT_ID}&response_type=code&scope=identify&redirect_uri=${encodeURIComponent(E.BASE_URL + '/auth/callback')}`);
});
app.get('/auth/callback', async (req, res) => {
  try {
    const t = await fetch(DISCORD + '/oauth2/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ client_id: E.DISCORD_CLIENT_ID, client_secret: E.DISCORD_CLIENT_SECRET, grant_type: 'authorization_code', code: req.query.code, redirect_uri: E.BASE_URL + '/auth/callback' }) }).then(r => r.json());
    const me = await fetch(DISCORD + '/users/@me', { headers: { Authorization: 'Bearer ' + t.access_token } }).then(r => r.json());
    let [u] = await q('SELECT * FROM web_users WHERE discord_user_id=$1', [me.id]);
    if (!u && me.id === E.OWNER_DISCORD_ID)
      [u] = await q('INSERT INTO web_users(discord_user_id,is_owner) VALUES($1,true) RETURNING *', [me.id]);
    if (!u || u.status !== 'active') return res.status(403).send('حسابك غير مصرّح له بالدخول');
    await q('UPDATE web_users SET last_login_at=now() WHERE id=$1', [u.id]);
    setCookie(res, u); res.redirect('/');
  } catch (e) { res.status(500).send('فشل تسجيل الدخول'); }
});
app.get('/auth/demo', async (req, res) => {   // وضع تجريبي فقط
  if (E.DEMO !== '1') return res.status(404).end();
  let [u] = await q('SELECT * FROM web_users WHERE is_owner');
  if (!u) [u] = await q('INSERT INTO web_users(discord_user_id,is_owner) VALUES($1,true) RETURNING *', ['demo-owner']);
  setCookie(res, u); res.redirect('/');
});
app.post('/auth/logout', (req, res) => res.clearCookie('t').json({ ok: 1 }));
app.get('/api/me', loadUser, (req, res) => res.json({ id: req.user.id, discord_user_id: req.user.discord_user_id, is_owner: req.user.is_owner, perms: [...req.user.perms], demo: E.DEMO === '1', bot: !!(E.DISCORD_BOT_TOKEN && E.GUILD_ID) }));

const api = express.Router(); api.use(loadUser); app.use('/api', api);

// ---------- Discord sync ----------
const bot = path => fetch(DISCORD + path, { headers: { Authorization: 'Bot ' + E.DISCORD_BOT_TOKEN } }).then(async r => { if (!r.ok) throw new Error(`Discord ${r.status}: ${await r.text()}`); return r.json(); });
api.post('/sync', need('bot.settings'), async (req, res) => {
  if (!E.DISCORD_BOT_TOKEN || !E.GUILD_ID) return res.status(400).json({ error: 'البوت غير مُعدّ. أضف DISCORD_BOT_TOKEN و GUILD_ID' });
  const [log] = await q("INSERT INTO sync_logs(guild_id,trigger,status) VALUES($1,'manual','running') RETURNING id", [E.GUILD_ID]);
  try {
    const g = await bot(`/guilds/${E.GUILD_ID}?with_counts=true`);
    await q(`INSERT INTO discord_guilds VALUES($1,$2,$3,$4,now()) ON CONFLICT(guild_id) DO UPDATE SET name=$2,icon_hash=$3,member_count=$4,last_synced_at=now()`, [g.id, g.name, g.icon, g.approximate_member_count]);
    const roles = await bot(`/guilds/${E.GUILD_ID}/roles`);
    await q('UPDATE discord_roles SET is_deleted=true WHERE guild_id=$1', [g.id]);
    for (const r of roles) await q(`INSERT INTO discord_roles VALUES($1,$2,$3,$4,$5,false,now()) ON CONFLICT(role_id) DO UPDATE SET name=$3,color=$4,position=$5,is_deleted=false,last_synced_at=now()`, [r.id, g.id, r.name, r.color, r.position]);
    // ربط تلقائي فقط عند تطابق الاسم تماماً (بدون تخمين)
    await q(`UPDATE staff_roles s SET discord_role_id=d.role_id, name_original=d.name, name_status='confirmed'
             FROM discord_roles d WHERE s.discord_role_id IS NULL AND d.guild_id=$1 AND d.name=s.name_original AND NOT d.is_deleted
             AND d.role_id NOT IN (SELECT discord_role_id FROM staff_roles WHERE discord_role_id IS NOT NULL)`, [g.id]);
    await q('UPDATE discord_members SET is_present=false WHERE guild_id=$1', [g.id]);
    let after = '0', n = 0;
    for (;;) {
      const ms = await bot(`/guilds/${E.GUILD_ID}/members?limit=1000&after=${after}`);
      if (!ms.length) break;
      for (const m of ms) {
        const u = m.user; n++;
        await q(`INSERT INTO discord_members VALUES($1,$2,$3,$4,$5,$6,$7,NULL,true,now()) ON CONFLICT(guild_id,user_id) DO UPDATE SET username=$3,global_name=$4,nickname=$5,avatar_hash=$6,joined_at=$7,is_present=true,left_at=NULL,last_synced_at=now()`, [g.id, u.id, u.username, u.global_name, m.nick, u.avatar, m.joined_at]);
        await q('DELETE FROM member_discord_roles WHERE guild_id=$1 AND user_id=$2', [g.id, u.id]);
        for (const rid of m.roles) await q('INSERT INTO member_discord_roles VALUES($1,$2,$3) ON CONFLICT DO NOTHING', [g.id, u.id, rid]);
        // إنشاء ملف إداري تلقائياً لمن يحمل رتبة مربوطة ومعلّمة كرتبة إدارية
        const sr = await q('SELECT id FROM staff_roles WHERE discord_role_id=ANY($1) AND is_staff_role AND NOT is_archived', [m.roles]);
        if (sr.length) {
          const [p] = await q('INSERT INTO staff_profiles(guild_id,discord_user_id) VALUES($1,$2) ON CONFLICT(guild_id,discord_user_id) DO UPDATE SET updated_at=staff_profiles.updated_at RETURNING id', [g.id, u.id]);
          for (const r of sr) if (!(await q('SELECT 1 FROM staff_role_assignments WHERE profile_id=$1 AND staff_role_id=$2 AND ended_at IS NULL', [p.id, r.id])).length)
            await q('INSERT INTO staff_role_assignments(profile_id,staff_role_id) VALUES($1,$2)', [p.id, r.id]);
          await q('UPDATE staff_role_assignments SET ended_at=now() WHERE profile_id=$1 AND ended_at IS NULL AND staff_role_id<>ALL($2)', [p.id, sr.map(r => r.id)]);
        }
      }
      after = ms[ms.length - 1].user.id; if (ms.length < 1000) break;
    }
    await q('UPDATE discord_members SET left_at=now() WHERE guild_id=$1 AND NOT is_present AND left_at IS NULL', [g.id]);
    await q("UPDATE sync_logs SET status='success',members_seen=$2,roles_seen=$3,finished_at=now() WHERE id=$1", [log.id, n, roles.length]);
    await audit(req.user, 'sync', 'guild', g.id, null, { members: n, roles: roles.length }, req);
    res.json({ ok: 1, members: n, roles: roles.length });
  } catch (e) {
    await q("UPDATE sync_logs SET status='failed',error=$2,finished_at=now() WHERE id=$1", [log.id, e.message]);
    res.status(500).json({ error: e.message });
  }
});
api.get('/sync-logs', need('bot.settings'), async (req, res) => res.json(await q('SELECT * FROM sync_logs ORDER BY id DESC LIMIT 20')));

// ---------- Dashboard ----------
api.get('/dashboard', need('reports.view'), async (req, res) => {
  const one = async s => (await q(s))[0];
  res.json({
    members: (await one('SELECT COALESCE(SUM(member_count),0)::int n FROM discord_guilds')).n,
    staff: (await one("SELECT COUNT(*)::int n FROM staff_profiles WHERE account_status<>'archived'")).n,
    byRole: await q(`SELECT s.id, s.name_original name, s.name_status, COUNT(a.id)::int count FROM staff_roles s
      LEFT JOIN staff_role_assignments a ON a.staff_role_id=s.id AND a.ended_at IS NULL WHERE NOT s.is_archived GROUP BY s.id ORDER BY s.list_order`),
    byDept: await q('SELECT d.name, COUNT(p.id)::int count FROM departments d LEFT JOIN staff_profiles p ON p.department_id=d.id GROUP BY d.id'),
    unreviewedRoles: (await one("SELECT COUNT(*)::int n FROM staff_roles s WHERE NOT EXISTS(SELECT 1 FROM role_responsibilities r WHERE r.staff_role_id=s.id AND r.status='approved')")).n,
    openComplaints: (await one("SELECT COUNT(*)::int n FROM complaints WHERE status IN ('open','reviewing')")).n,
    overdueTasks: (await one("SELECT COUNT(*)::int n FROM tasks WHERE status IN ('open','in_progress') AND due_at<now()")).n,
    newApplications: (await one("SELECT COUNT(*)::int n FROM recruitment_applications WHERE status='new'")).n,
    lastSync: (await q('SELECT status, finished_at, error FROM sync_logs ORDER BY id DESC LIMIT 1'))[0] || null,
    latestDecisions: await q('SELECT decision_no, type, decided_at, exec_status FROM staff_decisions ORDER BY id DESC LIMIT 8'),
  });
});

// ---------- Staff ----------
api.get('/staff', need('staff.view'), async (req, res) => {
  const { search = '', role = '', dept = '' } = req.query;
  res.json(await q(`SELECT p.id, p.discord_user_id, p.account_status, p.position_title, d.name dept, m.username, m.global_name, m.nickname, m.avatar_hash,
      COALESCE(json_agg(DISTINCT s.name_original) FILTER (WHERE s.id IS NOT NULL),'[]') roles
    FROM staff_profiles p LEFT JOIN discord_members m ON m.guild_id=p.guild_id AND m.user_id=p.discord_user_id
    LEFT JOIN departments d ON d.id=p.department_id
    LEFT JOIN staff_role_assignments a ON a.profile_id=p.id AND a.ended_at IS NULL LEFT JOIN staff_roles s ON s.id=a.staff_role_id
    WHERE ($1='' OR m.username ILIKE '%'||$1||'%' OR m.global_name ILIKE '%'||$1||'%' OR p.discord_user_id=$1 OR s.discord_role_id=$1)
      AND ($2='' OR s.id=$2::bigint) AND ($3='' OR p.department_id=$3::bigint)
    GROUP BY p.id, d.name, m.username, m.global_name, m.nickname, m.avatar_hash ORDER BY p.id LIMIT 200`, [search, role, dept]));
});
api.get('/staff/:id', need('staff.view'), async (req, res) => {
  const [p] = await q(`SELECT p.*, d.name dept, m.username, m.global_name, m.nickname, m.avatar_hash, m.joined_at, m.last_synced_at
    FROM staff_profiles p LEFT JOIN discord_members m ON m.guild_id=p.guild_id AND m.user_id=p.discord_user_id LEFT JOIN departments d ON d.id=p.department_id WHERE p.id=$1`, [req.params.id]);
  if (!p) return res.status(404).json({ error: 'غير موجود' });
  const sens = req.user.perms.has('sensitive.view');
  res.json({ ...p, internal_notes: sens ? p.internal_notes : undefined,
    roles: await q('SELECT s.name_original, s.discord_role_id, a.assigned_at, a.ended_at FROM staff_role_assignments a JOIN staff_roles s ON s.id=a.staff_role_id WHERE a.profile_id=$1 ORDER BY a.assigned_at DESC', [p.id]),
    decisions: await q('SELECT decision_no,type,reason,decided_at,exec_status FROM staff_decisions WHERE profile_id=$1 ORDER BY id DESC', [p.id]),
    discipline: sens ? await q('SELECT kind,reason,created_at,appeal_status FROM disciplinary_records WHERE profile_id=$1 ORDER BY id DESC', [p.id]) : null,
    tasks: await q('SELECT title,status,due_at FROM tasks WHERE profile_id=$1 ORDER BY id DESC', [p.id]) });
});
api.patch('/staff/:id', need('staff.edit'), async (req, res) => {
  const f = ['department_id', 'position_title', 'direct_supervisor', 'account_status', 'internal_notes', 'appointed_at'].filter(k => k in req.body);
  if (!f.length) return res.status(400).json({ error: 'لا حقول' });
  const [old] = await q('SELECT * FROM staff_profiles WHERE id=$1', [req.params.id]);
  const [n] = await q(`UPDATE staff_profiles SET ${f.map((k, i) => `${k}=$${i + 2}`).join(',')}, updated_at=now() WHERE id=$1 RETURNING *`, [req.params.id, ...f.map(k => req.body[k])]);
  await audit(req.user, 'update', 'staff_profile', n.id, old, n, req); res.json(n);
});

// ---------- Roles / responsibilities / permissions ----------
api.get('/roles', need('staff.view'), async (req, res) => res.json(await q(`SELECT s.*, d.name discord_name, d.color,
  (SELECT status FROM role_responsibilities r WHERE r.staff_role_id=s.id ORDER BY id DESC LIMIT 1) resp_status FROM staff_roles s LEFT JOIN discord_roles d ON d.role_id=s.discord_role_id ORDER BY s.list_order`)));
api.get('/discord-roles', need('roles.manage'), async (req, res) => res.json(await q('SELECT role_id,name,color,position FROM discord_roles WHERE NOT is_deleted ORDER BY position DESC')));
api.patch('/roles/:id', need('roles.manage'), async (req, res) => {
  const f = ['discord_role_id', 'admin_level', 'is_staff_role', 'is_archived', 'name_original'].filter(k => k in req.body);
  const [old] = await q('SELECT * FROM staff_roles WHERE id=$1', [req.params.id]);
  const [n] = await q(`UPDATE staff_roles SET ${f.map((k, i) => `${k}=$${i + 2}`).join(',')} WHERE id=$1 RETURNING *`, [req.params.id, ...f.map(k => req.body[k] === '' ? null : req.body[k])]);
  await audit(req.user, 'update', 'staff_role', n.id, old, n, req); res.json(n);
});
api.get('/roles/:id/responsibilities', need('staff.view'), async (req, res) => res.json((await q('SELECT * FROM role_responsibilities WHERE staff_role_id=$1 ORDER BY id DESC LIMIT 1', [req.params.id]))[0] || null));
api.put('/roles/:id/responsibilities', need('roles.manage'), async (req, res) => {
  const b = req.body, F = ['objective', 'core_duties', 'daily_weekly', 'limits', 'forbidden', 'promotion_rules', 'revocation_rules', 'kpis', 'official_desc'];
  const status = b.approve ? 'approved' : 'suggested';
  const [r] = await q(`INSERT INTO role_responsibilities(staff_role_id,${F},status,approved_by,approved_at) VALUES($1,${F.map((_, i) => '$' + (i + 2))},$${F.length + 2},$${F.length + 3},${b.approve ? 'now()' : 'NULL'}) RETURNING *`,
    [req.params.id, ...F.map(k => b[k] ?? null), status, b.approve ? req.user.id : null]);
  await audit(req.user, 'upsert', 'role_responsibilities', r.id, null, r, req); res.json(r);
});
api.get('/permissions', need('roles.manage'), async (req, res) => res.json({ all: await q('SELECT * FROM permissions ORDER BY key'), granted: await q('SELECT * FROM role_permissions') }));
api.put('/roles/:id/permissions', need('roles.manage'), async (req, res) => {
  const keys = (req.body.keys || []).filter(k => req.user.perms.has(k)); // لا يمنح ما لا يملكه
  await q('DELETE FROM role_permissions WHERE staff_role_id=$1', [req.params.id]);
  for (const k of keys) await q('INSERT INTO role_permissions VALUES($1,$2)', [req.params.id, k]);
  await audit(req.user, 'set_permissions', 'staff_role', req.params.id, null, { keys }, req); res.json({ ok: 1, keys });
});
api.get('/departments', need('staff.view'), async (req, res) => res.json(await q('SELECT * FROM departments WHERE NOT is_archived ORDER BY name')));
api.post('/departments', need('roles.manage'), async (req, res) => { const [d] = await q('INSERT INTO departments(name,description) VALUES($1,$2) RETURNING *', [req.body.name, req.body.description]); await audit(req.user, 'create', 'department', d.id, null, d, req); res.json(d); });

// ---------- Decisions & audit ----------
api.get('/decisions', need('staff.view'), async (req, res) => res.json(await q('SELECT d.*, m.username FROM staff_decisions d JOIN staff_profiles p ON p.id=d.profile_id LEFT JOIN discord_members m ON m.user_id=p.discord_user_id ORDER BY d.id DESC LIMIT 200')));
const decisionPerm = { promotion: 'staff.promote', demotion: 'staff.promote', appointment: 'staff.add', dismissal: 'staff.archive', warning: 'penalties.issue', suspension: 'penalties.issue', transfer: 'staff.edit', permission_change: 'roles.manage', reactivation: 'staff.edit' };
api.post('/decisions', async (req, res) => {
  const { profile_id, type, reason, details } = req.body;
  if (!decisionPerm[type]) return res.status(400).json({ error: 'نوع قرار غير صالح' });
  if (!req.user.perms.has(decisionPerm[type])) return res.status(403).json({ error: 'لا تملك الصلاحية' });
  if (!reason) return res.status(400).json({ error: 'السبب مطلوب' });
  await q('CREATE SEQUENCE IF NOT EXISTS decision_seq');
  const [d] = await q(`INSERT INTO staff_decisions(decision_no,profile_id,type,issued_by,reason,details)
    VALUES('DEC-'||to_char(now(),'YYYY')||'-'||lpad(nextval('decision_seq')::text,6,'0'),$1,$2,$3,$4,$5) RETURNING *`, [profile_id, type, req.user.id, reason, details]);
  if (type === 'warning' || type === 'suspension') await q('INSERT INTO disciplinary_records(profile_id,decision_id,kind,reason,created_by) VALUES($1,$2,$3,$4,$5)', [profile_id, d.id, type, reason, req.user.id]);
  await audit(req.user, 'create', 'decision', d.id, null, d, req); res.json(d);
});
api.get('/audit', need('sensitive.view'), async (req, res) => res.json(await q('SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200')));

app.use(express.static('public'));
app.listen(E.PORT || 3000, () => console.log('Running on :' + (E.PORT || 3000)));
