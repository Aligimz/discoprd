-- =====================================================================
-- Discord Staff Management System — Phase 1: Database + RBAC + Audit
-- PostgreSQL 14+
-- All Discord IDs are stored as TEXT (snowflakes exceed JS safe integers).
-- Discord-synced data is kept separate from owner-managed admin data.
-- =====================================================================

BEGIN;

-- ---------- Web accounts (auth) ----------
CREATE TABLE web_users (
  id              BIGSERIAL PRIMARY KEY,
  discord_user_id TEXT UNIQUE NOT NULL,         -- login via Discord OAuth2
  is_owner        BOOLEAN NOT NULL DEFAULT FALSE,
  status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','archived')),
  created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_login_at   TIMESTAMPTZ
);
-- Only one owner account allowed
CREATE UNIQUE INDEX one_owner ON web_users (is_owner) WHERE is_owner;

-- ======================= DISCORD-SYNCED DATA ========================
CREATE TABLE discord_guilds (
  guild_id       TEXT PRIMARY KEY,
  name           TEXT,
  icon_hash      TEXT,
  member_count   INT,
  last_synced_at TIMESTAMPTZ
);

CREATE TABLE discord_roles (
  role_id        TEXT PRIMARY KEY,               -- real Discord Role ID
  guild_id       TEXT NOT NULL REFERENCES discord_guilds(guild_id),
  name           TEXT NOT NULL,                  -- original name as in Discord, never guessed
  color          INT,
  position       INT,                            -- Discord hierarchy position
  is_deleted     BOOLEAN NOT NULL DEFAULT FALSE, -- archive, never hard delete
  last_synced_at TIMESTAMPTZ
);

CREATE TABLE discord_members (
  guild_id        TEXT NOT NULL REFERENCES discord_guilds(guild_id),
  user_id         TEXT NOT NULL,
  username        TEXT,
  global_name     TEXT,
  nickname        TEXT,
  avatar_hash     TEXT,
  joined_at       TIMESTAMPTZ,
  left_at         TIMESTAMPTZ,
  is_present      BOOLEAN NOT NULL DEFAULT TRUE,
  last_synced_at  TIMESTAMPTZ,
  PRIMARY KEY (guild_id, user_id)
);

CREATE TABLE member_discord_roles (            -- raw sync mirror
  guild_id TEXT NOT NULL,
  user_id  TEXT NOT NULL,
  role_id  TEXT NOT NULL REFERENCES discord_roles(role_id),
  PRIMARY KEY (guild_id, user_id, role_id),
  FOREIGN KEY (guild_id, user_id) REFERENCES discord_members(guild_id, user_id) ON DELETE CASCADE
);

-- ===================== OWNER-MANAGED ADMIN DATA ======================
-- Sync NEVER touches the tables below.

CREATE TABLE departments (
  id          BIGSERIAL PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  description TEXT,
  head_profile_id BIGINT,                         -- FK added below
  is_archived BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE staff_profiles (
  id                BIGSERIAL PRIMARY KEY,
  guild_id          TEXT NOT NULL,
  discord_user_id   TEXT NOT NULL,
  department_id     BIGINT REFERENCES departments(id),
  position_title    TEXT,
  direct_supervisor BIGINT REFERENCES staff_profiles(id),
  deputy_of         BIGINT REFERENCES staff_profiles(id),
  appointed_at      TIMESTAMPTZ,
  account_status    TEXT NOT NULL DEFAULT 'active'
                    CHECK (account_status IN ('active','suspended','on_leave','archived')),
  internal_notes    TEXT,
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (guild_id, discord_user_id)
);
ALTER TABLE departments
  ADD CONSTRAINT fk_dept_head FOREIGN KEY (head_profile_id) REFERENCES staff_profiles(id);

-- Owner-defined meaning of each Discord role (the "official" admin level)
CREATE TABLE staff_roles (
  id               BIGSERIAL PRIMARY KEY,
  discord_role_id  TEXT UNIQUE REFERENCES discord_roles(role_id),  -- NULL until linked
  name_original    TEXT NOT NULL,                 -- name exactly as given
  name_status      TEXT NOT NULL DEFAULT 'unconfirmed'
                   CHECK (name_status IN ('confirmed','unconfirmed')),
  group_no         SMALLINT,                      -- 1..4 from the initial list
  list_order       SMALLINT,                      -- initial list order only, NOT hierarchy
  admin_level      INT,                           -- set by owner; NULL = not defined
  is_staff_role    BOOLEAN NOT NULL DEFAULT TRUE,
  is_archived      BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE role_responsibilities (
  id               BIGSERIAL PRIMARY KEY,
  staff_role_id    BIGINT NOT NULL REFERENCES staff_roles(id),
  objective        TEXT,
  core_duties      TEXT,
  daily_weekly     TEXT,
  limits           TEXT,
  forbidden        TEXT,
  promotion_rules  TEXT,
  revocation_rules TEXT,
  kpis             TEXT,
  official_desc    TEXT,
  reviewed_by_role BIGINT REFERENCES staff_roles(id),
  status           TEXT NOT NULL DEFAULT 'suggested'
                   CHECK (status IN ('suggested','approved')),  -- suggestions never grant permissions
  approved_by      BIGINT REFERENCES web_users(id),
  approved_at      TIMESTAMPTZ,
  updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE staff_role_assignments (
  id            BIGSERIAL PRIMARY KEY,
  profile_id    BIGINT NOT NULL REFERENCES staff_profiles(id),
  staff_role_id BIGINT NOT NULL REFERENCES staff_roles(id),
  assigned_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  ended_at      TIMESTAMPTZ                      -- history kept, never deleted
);

CREATE TABLE organizational_relationships (
  id             BIGSERIAL PRIMARY KEY,
  parent_role_id BIGINT NOT NULL REFERENCES staff_roles(id),
  child_role_id  BIGINT NOT NULL REFERENCES staff_roles(id),
  relation       TEXT NOT NULL DEFAULT 'supervises',
  CHECK (parent_role_id <> child_role_id),
  UNIQUE (parent_role_id, child_role_id)
);

-- ============================== RBAC =================================
CREATE TABLE permissions (
  key         TEXT PRIMARY KEY,                   -- e.g. 'staff.view'
  description TEXT NOT NULL,
  is_sensitive BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE role_permissions (
  staff_role_id BIGINT NOT NULL REFERENCES staff_roles(id) ON DELETE CASCADE,
  permission_key TEXT NOT NULL REFERENCES permissions(key),
  PRIMARY KEY (staff_role_id, permission_key)
);

CREATE TABLE user_permissions (                   -- per-user extra grant / deny
  web_user_id    BIGINT NOT NULL REFERENCES web_users(id) ON DELETE CASCADE,
  permission_key TEXT NOT NULL REFERENCES permissions(key),
  effect         TEXT NOT NULL DEFAULT 'allow' CHECK (effect IN ('allow','deny')),
  granted_by     BIGINT REFERENCES web_users(id),
  granted_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (web_user_id, permission_key)
);

-- ======================= ADMINISTRATIVE RECORDS ======================
CREATE TABLE staff_decisions (
  id           BIGSERIAL PRIMARY KEY,
  decision_no  TEXT NOT NULL UNIQUE,              -- e.g. DEC-2026-000123
  profile_id   BIGINT NOT NULL REFERENCES staff_profiles(id),
  type         TEXT NOT NULL CHECK (type IN
    ('promotion','demotion','appointment','dismissal','warning','suspension',
     'transfer','permission_change','reactivation')),
  issued_by    BIGINT NOT NULL REFERENCES web_users(id),
  reason       TEXT NOT NULL,
  details      TEXT,
  exec_status  TEXT NOT NULL DEFAULT 'pending'
               CHECK (exec_status IN ('pending','executed','failed','cancelled')),
  decided_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE promotions (
  id          BIGSERIAL PRIMARY KEY,
  decision_id BIGINT NOT NULL REFERENCES staff_decisions(id),
  from_role   BIGINT REFERENCES staff_roles(id),
  to_role     BIGINT REFERENCES staff_roles(id)
);

CREATE TABLE disciplinary_records (
  id          BIGSERIAL PRIMARY KEY,
  profile_id  BIGINT NOT NULL REFERENCES staff_profiles(id),
  decision_id BIGINT REFERENCES staff_decisions(id),
  kind        TEXT NOT NULL CHECK (kind IN ('warning','penalty','suspension')),
  reason      TEXT NOT NULL,
  expires_at  TIMESTAMPTZ,
  appeal_status TEXT NOT NULL DEFAULT 'none' CHECK (appeal_status IN ('none','pending','accepted','rejected')),
  created_by  BIGINT REFERENCES web_users(id),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE tasks (
  id          BIGSERIAL PRIMARY KEY,
  profile_id  BIGINT NOT NULL REFERENCES staff_profiles(id),
  title       TEXT NOT NULL,
  description TEXT,
  due_at      TIMESTAMPTZ,
  status      TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','in_progress','done','cancelled')),
  assigned_by BIGINT REFERENCES web_users(id),
  completed_at TIMESTAMPTZ
);

CREATE TABLE complaints (
  id            BIGSERIAL PRIMARY KEY,
  against_profile_id BIGINT REFERENCES staff_profiles(id),
  submitted_by_discord_id TEXT,
  body          TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','reviewing','resolved','dismissed')),
  handled_by    BIGINT REFERENCES web_users(id),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE recruitment_applications (
  id               BIGSERIAL PRIMARY KEY,
  applicant_discord_id TEXT NOT NULL,
  answers          JSONB,
  status           TEXT NOT NULL DEFAULT 'new' CHECK (status IN ('new','reviewing','accepted','rejected')),
  reviewed_by      BIGINT REFERENCES web_users(id),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ===================== AUDIT / SYNC / SETTINGS =======================
CREATE TABLE audit_logs (
  id         BIGSERIAL PRIMARY KEY,
  actor_id   BIGINT REFERENCES web_users(id),
  action     TEXT NOT NULL,
  entity     TEXT NOT NULL,
  entity_id  TEXT,
  before     JSONB,
  after      JSONB,
  ip         INET,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Audit log is append-only
CREATE FUNCTION forbid_audit_change() RETURNS trigger AS $$
BEGIN RAISE EXCEPTION 'audit_logs is append-only'; END $$ LANGUAGE plpgsql;
CREATE TRIGGER audit_no_update BEFORE UPDATE OR DELETE ON audit_logs
  FOR EACH ROW EXECUTE FUNCTION forbid_audit_change();

-- Decisions: date and issuer are immutable (changes must go through a new audited record)
CREATE FUNCTION lock_decision_core() RETURNS trigger AS $$
BEGIN
  IF NEW.decided_at <> OLD.decided_at OR NEW.issued_by <> OLD.issued_by
     OR NEW.decision_no <> OLD.decision_no THEN
    RAISE EXCEPTION 'decision date / issuer / number are immutable';
  END IF;
  RETURN NEW;
END $$ LANGUAGE plpgsql;
CREATE TRIGGER decisions_lock BEFORE UPDATE ON staff_decisions
  FOR EACH ROW EXECUTE FUNCTION lock_decision_core();

CREATE TABLE sync_logs (
  id          BIGSERIAL PRIMARY KEY,
  guild_id    TEXT,
  trigger     TEXT CHECK (trigger IN ('manual','scheduled','event')),
  status      TEXT CHECK (status IN ('running','success','partial','failed')),
  members_seen INT, roles_seen INT,
  error       TEXT,
  started_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at TIMESTAMPTZ
);

CREATE TABLE system_settings (
  key        TEXT PRIMARY KEY,
  value      JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ON staff_profiles (department_id);
CREATE INDEX ON staff_role_assignments (profile_id) WHERE ended_at IS NULL;
CREATE INDEX ON audit_logs (entity, entity_id);
CREATE INDEX ON discord_members (username);

-- ============================== SEEDS ================================
INSERT INTO permissions (key, description, is_sensitive) VALUES
 ('staff.view','عرض بيانات الإداريين',false),
 ('staff.edit','تعديل الملفات الإدارية',false),
 ('staff.add','إضافة إداري',false),
 ('staff.archive','أرشفة إداري',false),
 ('roles.manage','إدارة الرتب',true),
 ('roles.assign','منح الرتب وسحبها',true),
 ('staff.promote','ترقية وتنزيل الإداريين',true),
 ('recruitment.manage','إدارة التوظيف',false),
 ('complaints.review','مراجعة الشكاوى',false),
 ('penalties.issue','إصدار العقوبات',true),
 ('appeals.review','مراجعة الاعتراضات',true),
 ('tasks.manage','إدارة المهام',false),
 ('reports.view','عرض التقارير',false),
 ('data.export','تصدير البيانات',true),
 ('sensitive.view','عرض السجلات الحساسة',true),
 ('bot.settings','إدارة إعدادات البوت',true),
 ('users.manage','إدارة حسابات المستخدمين',true),
 ('system.settings','إدارة إعدادات النظام',true);

-- Initial role list (names exactly as provided; none are linked to Discord yet).
-- Items 11, 12, 16, 23, 31, 41 are symbol-only / truncated -> stay 'unconfirmed'
-- until imported from Discord. list_order is NOT the hierarchy.
INSERT INTO staff_roles (name_original, name_status, group_no, list_order) VALUES
 ('Owner','unconfirmed',1,1),('Co Owner','unconfirmed',1,2),('Owner Allies','unconfirmed',1,3),
 ('Co Owner Alias','unconfirmed',1,4),('Consultant','unconfirmed',1,5),('Marshal','unconfirmed',1,6),
 ('Majesty','unconfirmed',1,7),('Overseer','unconfirmed',1,8),('مسؤول الإداري','unconfirmed',1,9),
 ('Development Team','unconfirmed',1,10),('[رتبة بالرمز † — الاسم غير مؤكد]','unconfirmed',1,11),
 ('[رتبة بالرمز ❄ — الاسم غير مؤكد]','unconfirmed',1,12),('The king','unconfirmed',1,13),
 ('Hand of the king','unconfirmed',1,14),('Legacy','unconfirmed',1,15),
 ('[رتبة الساعة الرملية ⌛ — الاسم غير مؤكد]','unconfirmed',2,16),('Grand Master','unconfirmed',2,17),
 ('Master','unconfirmed',2,18),('Governor','unconfirmed',2,19),('Co Governor','unconfirmed',2,20),
 ('Colonel','unconfirmed',2,21),('الإدارة العليا','unconfirmed',2,22),
 ('[رتبة النجمة ★ — الاسم غير مؤكد]','unconfirmed',2,23),('Founder','unconfirmed',2,24),
 ('Co Founder','unconfirmed',2,25),('Big Boos','unconfirmed',2,26),('Boos','unconfirmed',2,27),
 ('Operator','unconfirmed',2,28),('President','unconfirmed',2,29),('Higher Manager','unconfirmed',2,30),
 ('[رتبة الشارة ♟ — الاسم غير مؤكد]','unconfirmed',3,31),('Admin of the… (مقطوع)','unconfirmed',3,32),
 ('Executive','unconfirmed',3,33),('Commander','unconfirmed',3,34),('Staff Manager','unconfirmed',3,35),
 ('Controller','unconfirmed',3,36),('Director','unconfirmed',3,37),('Mythical','unconfirmed',3,38),
 ('Technical Manager','unconfirmed',3,39),('الإدارة العشراء','unconfirmed',3,40),
 ('[رتبة الحصان ♞ — الاسم غير مؤكد]','unconfirmed',4,41),('Head Manager','unconfirmed',4,42),
 ('Admin Manger','unconfirmed',4,43),('Supr Admin','unconfirmed',4,44),('Admin','unconfirmed',4,45),
 ('Mod','unconfirmed',4,46),('Supervisor','unconfirmed',4,47),('Visor','unconfirmed',4,48),
 ('Trusted','unconfirmed',4,49),('الإدارة الصفراء','unconfirmed',4,50);

COMMIT;
