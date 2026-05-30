# ══════════════════════════════════════════════════════════════════
#  Security Bot  –  Full Refactor v2.0
#  pip install discord.py aiohttp
#
# ── ประวัติการแก้ไข ────────────────────────────────────────────────
#
#  [Session 1] แก้ไขพื้นฐาน
#  • เพิ่ม join_tracker ใน __init__ (ป้องกัน AttributeError ตอน anti-raid)
#  • แก้ quarantine: strip roles ก่อน แล้วค่อย add blacklist role แยกขั้นตอน
#    (แก้ปัญหา blacklist role ไม่ถูกใส่เพราะ edit() ทับ add_roles())
#
#  [Session 2] Role Manager + ความเร็ว Advanced Lockdown
#  • เพิ่ม role_manager config key: member_roles, dangerous_roles, exempt_roles
#  • แก้ do_advanced_lockdown() — ถ้าตั้ง dangerous_roles ไว้จะยิงตรงแทน loop ทุก role
#    (ลดเวลาจาก 2-3 วิ เหลือ ~200-500ms)
#  • เพิ่ม API: GET/POST /api/role-manager
#  • เพิ่มหน้า Role Manager ใน Dashboard
#
#  [Session 3] เก็บ Logs ข้ามการรีสตาร์ท
#  • เพิ่ม RETENTION_DAYS = 7 และ _prune_old() ตัดข้อมูลเกิน 7 วัน
#  • save_guild_data() บันทึก logs.json (suspicious_alerts + audit_log) คู่กับ data.json
#  • load_guild_data() โหลด logs.json กลับเข้า RAM ตอน startup
#
#  [Session 4] ห้องที่ถูกลบ + Time Window + Timeout Duration
#  • เพิ่ม API: GET /api/channels/validate — ตรวจห้องใน config ที่หายไปจาก Discord
#  • เพิ่ม API: POST /api/channels/clear — ลบห้องที่หายออกจาก config
#  • Dashboard แสดง banner แจ้งเตือนอัตโนมัติเมื่อพบห้องที่ถูกลบ
#  • Time Window เลือกหน่วยได้: วินาที / นาที / ชั่วโมง
#  • Timeout punishment: มีแถบกำหนดระยะเวลาได้ (วินาที/นาที/ชั่วโมง/วัน)
#  • apply_punishment() รับ timeout_seconds จาก config แทนค่า default
#
#  [Session 5] Server Banner Image
#  • api_stats คืน banner_url และ splash_url ของ guild
#  • Dashboard แสดงรูปพื้นหลัง server ใน server card (ใช้ banner ถ้ามี ไม่มีใช้ splash)
#  • ถ้า server ไม่มี banner จะแสดง gradient เดิม
#
#  [Session 6] ตรวจสอบ Dashboard → Bot sync
#  • แก้ Voice Abuse: window ใน saveConfig() ไม่ได้ผ่าน toSeconds() → แก้แล้ว
#  • เพิ่ม unit selector (วินาที/นาที/ชั่วโมง) สำหรับ Voice Abuse window ใน Dashboard
#  • เพิ่ม vaWinDisplay/vaWinUnit calculation ใน renderVoice()
#
#  [Session 7] Event-driven Layer (ชั้นที่ 1) — ป้องกัน 2 ชั้น
#  • เพิ่ม _ACTION_FEATURE_MAP: map discord action → feature_key ครบทุก action
#  • ขยาย on_audit_log_entry_create ให้จับทุก Anti-Nuke action
#    รับ actor จาก Gateway โดยตรง ไม่ต้องยิง HTTP audit_logs query → เร็วขึ้น ~200-500ms
#  • ส่ง actor ให้ทั้งระบบ A (check_feature) และระบบ B (do_advanced_lockdown)
#  • ลบ _audit() HTTP pull ออกจาก event handlers ทุกตัว:
#    on_member_ban, on_member_remove, on_guild_channel_create/delete/update,
#    on_guild_role_create/delete/update, on_guild_update, on_member_update
#
#  [Session 8] Deep Scan + Bot Action Log + Blacklist Monitor + Auto-classify
#
#  [Session 10] Speed Optimization — ทุก feature เร็วเท่ากัน
#  • เพิ่ม _VOICE_ABUSE_AUDIT_ACTIONS + _FEATURE_RECORD_MAP เป็น module-level constants
#  • on_audit_log_entry_create: จับ Voice Abuse จาก Gateway ตรงๆ (ไม่ต้อง HTTP audit_logs)
#    → เรียก _handle_voice_abuse_entry() ผ่าน create_task ทันที
#  • on_audit_log_entry_create: เพิ่ม record_action() ทุก action → Suspicious Tracker ครบ
#    รวม anti_bot_add, anti_prune, anti_integration ที่เคยไม่ถูก record
#  • on_member_join (Anti-Bot Add): ลบ HTTP audit_logs pull ออก
#    → on_audit_log_entry_create จัดการ punish inviter แล้ว, on_member_join แค่เตะบอทออก
#  • on_voice_state_update: ลบ HTTP audit_logs pull ออก (ย้ายไป on_audit_log_entry_create)
#  • check_feature(): ลบ fetch_member() ออกจาก hot path
#    → ถ้าไม่อยู่ใน cache ข้ามได้เลย (member ออกไปแล้ว)
#  • do_advanced_lockdown STEP 2: ลบ save_guild_data() ออกจาก critical path
#    → ไม่ควร await I/O ระหว่าง lockdown, auto_save จัดการให้ทุก 5 นาที
#
#  • bot_log() — เพิ่ม detected_ms / punished_ms parameter
#  • apply_punishment() — รับ detected_ms → คำนวณ response time
#  • check_feature() — บันทึก detected_ms ตอนตรวจพบ
#  • embed ทุกจุด ใช้ custom emoji + ms timestamp + Discord timestamp
#  • เพิ่ม run_deep_scan() — scan ทุก member/role/channel/webhook ตอน startup
#    บันทึกผลเป็น deep_scan.json ใน data channel ของแต่ละ guild
#  • เพิ่ม bot_log() + ensure_bot_action_log() — ห้อง 🤖・bot-action-log
#    บอทรายงานทุก action ที่ตัวเองทำ (ban/kick/timeout/quarantine) พร้อม timestamp ms
#    และรายงานทุกครั้งที่สงสัยพฤติกรรมแต่ยังไม่จัดการ (สีส้ม)
#  • เพิ่ม blacklist_role_monitor task — ตรวจทุก 60 วินาที ถ้า blacklist role หายแจ้งเตือนทันที
#  • เพิ่ม api_role_manager_auto_classify() + POST /api/role-manager/auto-classify
#    ปุ่ม Auto-classify ใน Dashboard — บอทแยกยศอัตโนมัติตาม permission
#
# ── ประวัติ Audit (ตรวจสอบโค้ดย้อนหลัง) ──────────────────────────
#
#  [Audit Session 1]
#  • แก้: _prune_old ถูกเรียกก่อนประกาศ → ย้ายขึ้นมาก่อน load_guild_data
#    (ป้องกัน NameError ตอน startup) ✅
#
#  [Audit Session 2]
#  • แก้: guild.ban(delete_message_days=0) → delete_message_seconds=0
#    (delete_message_days ถูกลบใน discord.py เวอร์ชันใหม่) ✅
#
#  [Audit Session 3]
#  • แก้: Voice Abuse ส่ง mute_duration เป็นนาทีตรงๆ → แปลงเป็น seconds ก่อน
#  • แก้: _audit_role_give closure capture bug → ใช้ default argument แทน ✅
#
#  [Audit Session 4]
#  • แก้: api_lockdown() race condition — create_task → await do_lockdown ✅
#
#  [Audit Session 5]
#  • แก้: _prune_old() fallback ts = time.time() → ts = 0
#  • แก้: on_guild_update (anti_vanity) double-trigger HTTP query → ลบออก
#  • แก้: api_post_config lockdown toggle create_task → await
#  • แก้: Voice Abuse log แสดง len(track) หลัง reset → บันทึก triggered_count ก่อน
#  • แก้: loadConfig() element ID ผิด feat-dur-* → feat-timeout-dur-*
#  • แก้: loadStats() ใช้ log.error (Python) ใน JS → เปลี่ยนเป็น console.error ✅
#
# ───────────────────────────────────────────────────────────────────
#
#  ENV:
#    DISCORD_TOKEN  – token บอท
#    API_BASE_URL   – URL เว็บ (เช่น https://yourapp.railway.app)
#    PORT           – port web server (default 8080)
#    DATA_SERVER_ID – ID ของ Server หลักที่เก็บข้อมูลทุก guild
# ══════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════
#  โครงสร้างโค้ดโดยรวม  (อัปเดต Session 9)
#
#  บรรทัด    1–  175  │ Header: ENV, logging, regex, constants, สร้าง bot object
#  บรรทัด  176–  208  │ imports + ENV constants
#  บรรทัด  209–  294  │ SecurityBot.__init__ — ประกาศตัวแปรทั้งหมด
#  บรรทัด  295–  506  │ BIE (Behavioral Intelligence Engine)
#                    │   BIE_TRACKED (295), bie_record, bie_hourly_avg,
#                    │   bie_baseline_snapshot task
#  บรรทัด  507–  615  │ Config: _feature() (507), default_config()
#  บรรทัด  616–  635  │ get_cfg() — ดึง/สร้าง config พร้อม backward compat
#  บรรทัด  636–  686  │ Whitelist: is_whitelisted() (636), is_exempt()
#  บรรทัด  667–  738  │ Suspicious Behavior Tracker
#                    │   SUSPICIOUS_RULES (667), record_action() (687)
#  บรรทัด  739–  766  │ Audit Log (in-memory) — add_audit()
#  บรรทัด  767–  869  │ apply_punishment() — ban/kick/timeout/quarantine/log
#                    │   [Session 9] รับ detected_ms → คำนวณ response time
#  บรรทัด  870–  983  │ Data Channel System
#                    │   ensure_data_channel() (870), _prune_old(),
#                    │   load_guild_data(), save_guild_data()
#  บรรทัด  984–  996  │ auto_save task — background task บันทึก config ทุก 5 นาที
#  บรรทัด  997– 1133  │ Bot Action Log System [Session 8]
#                    │   BOT_ACTION_LOG_NAME (997), ensure_bot_action_log(),
#                    │   bot_log() (1041) — [Session 9] detected_ms/punished_ms/response time
#  บรรทัด 1134– 1341  │ Deep Scan System [Session 8]
#                    │   DEEP_SCAN_PERMS (1134), run_deep_scan()
#  บรรทัด 1342– 1372  │ Blacklist Role Monitor [Session 8]
#                    │   blacklist_role_monitor task (1342)
#  บรรทัด 1373– 1423  │ Auto-classify Roles API [Session 8]
#                    │   api_role_manager_auto_classify() (1373)
#  บรรทัด 1424– 1467  │ Token Manager
#                    │   create_token() (1424), verify_token(), cleanup_tokens
#  บรรทัด 1468– 1539  │ Log Channel System — send_log() (1468), create_log_channel()
#  บรรทัด 1540– 1658  │ Nuke Tracker — check_feature() sliding-window
#                    │   [Session 9] บันทึก detected_ms + embed พรีเมียม
#  บรรทัด 1659– 1738  │ Events: on_ready (1659), on_guild_join
#  บรรทัด 1739– 1894  │ Slash Commands
#                    │   /getcode (1739), /initbl, /lockdown, /whitelist
#  บรรทัด 1895– 2005  │ on_message() — AutoMod + routing Anti-Spam
#  บรรทัด 2006– 2015  │ _rate_check() — sliding-window helper
#  บรรทัด 2016– 2207  │ Anti-Spam [Session 9 embed]
#                    │   _check_text_spam (2016), _check_mass_mentions,
#                    │   _check_link_spam, _check_att_spam, _check_emoji_spam
#  บรรทัด 2208– 2240  │ Reaction Spam — on_reaction_add()
#  บรรทัด 2241– 2390  │ Join Gate — on_member_join() (2241), _disable_raid()
#  บรรทัด 2391– 2489  │ Server Lockdown — do_lockdown()
#  บรรทัด 2490– 2769  │ Anti-Nuke Events [Session 9 embed ทุกจุด]
#                    │   on_member_ban (2490), on_member_remove (2508),
#                    │   on_member_unban (2533), on_guild_channel_create (2550),
#                    │   on_guild_channel_delete (2573), on_guild_role_create (2599),
#                    │   on_guild_role_delete (2628), on_member_update (2662),
#                    │   on_guild_update/anti_vanity (2735)
#  บรรทัด 2771– 2905  │ Event-driven Layer [Session 7]
#                    │   _ACTION_FEATURE_MAP (2771), on_audit_log_entry_create (2791)
#  บรรทัด 2906– 3047  │ Voice Abuse [Session 9 embed]
#                    │   VOICE_ABUSE_ACTIONS (2906), on_voice_state_update() (2912)
#  บรรทัด 3048– 3373  │ Other Log Events [Session 9 embed]
#                    │   on_message_delete (3048), on_message_edit (3078),
#                    │   on_invite_create (3104)
#  บรรทัด 3374– 3769  │ Web API ชุดที่ 1
#                    │   jres() (3374), api_verify(), api_get_config(),
#                    │   api_post_config(), api_stats(), api_logs(),
#                    │   api_channels_validate(), api_channels_clear(),
#                    │   api_create_log_channel(), api_delete_log_channel(),
#                    │   api_roles(), api_members()
#  บรรทัด 3770– 4054  │ Advanced Lockdown [Session 9 embed]
#                    │   ADV_LOCK_PERMS (3770), _role_is_admin_like(),
#                    │   do_advanced_lockdown() (3793) — 5 ขั้นตอน
#  บรรทัด 4055– 4272  │ Web API ชุดที่ 2
#                    │   api_advanced_manage() (4055), api_lockdown(),
#                    │   api_role_manager_get(), api_role_manager_post(),
#                    │   api_member_detail(), api_save_member_exemptions(),
#                    │   api_role_channels(), api_suspicious_alerts(),
#                    │   api_mark_alert_read(), api_member_actions()
#  บรรทัด 4273– 7437  │ DASHBOARD_HTML — SPA inline HTML/CSS/JS (Chart.js, Lucide)
#  บรรทัด 7438– 7503  │ page_index() (7438), api_bie_stats() (7465)
#  บรรทัด 7504– 7555  │ Web Server — run_web() (7504), main() (7548), entrypoint
# ══════════════════════════════════════════════════════════════════

import os, json, asyncio, io, secrets, logging, re, time, math, statistics
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
import discord
from discord import app_commands
from discord.ext import tasks
from aiohttp import web

# ── ENV ────────────────────────────────────────────────────────────
BOT_TOKEN      = os.environ.get("DISCORD_TOKEN", "")
API_BASE_URL   = os.environ.get("API_BASE_URL", "http://localhost:8080")
PORT           = int(os.environ.get("PORT", "8080"))
DATA_SERVER_ID = int(os.environ.get("DATA_SERVER_ID", "0"))

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("SecurityBot")

# ── REGEX ──────────────────────────────────────────────────────────
RE_LINK   = re.compile(r"https?://\S+", re.I)
RE_INVITE = re.compile(r"discord(?:\.gg|app\.com/invite)/\S+", re.I)

# ── DANGEROUS PERMISSIONS ──────────────────────────────────────────
DANGEROUS_PERMS = [
    "administrator", "manage_guild", "manage_roles",
    "manage_channels", "ban_members", "kick_members",
    "mention_everyone", "manage_webhooks",
]

# ══════════════════════════════════════════════════════════════════
#  BOT
# ══════════════════════════════════════════════════════════════════
intents = discord.Intents.all()

class SecurityBot(discord.Client):
    def __init__(self):
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)
        self.guild_data: dict    = {}
        self.active_tokens: dict = {}
        self.data_lock            = asyncio.Lock()
        # per-user spam heat: uid → [timestamp, ...]
        self.heat: dict           = defaultdict(list)
        # per-guild save locks to avoid one slow guild blocking others
        self._save_locks: dict    = defaultdict(asyncio.Lock)
        # guilds currently in raid mode
        self.raid_mode: set       = set()
        # nuke tracking: guild_id → user_id → [(action, ts)]
        self.nuke_track: dict     = defaultdict(lambda: defaultdict(list))
        # voice abuse: guild_id → user_id → [(action, ts)]
        self.voice_track: dict    = defaultdict(lambda: defaultdict(list))
        # attachment spam: guild_id → user_id → [ts]
        self.att_track: dict      = defaultdict(lambda: defaultdict(list))
        # mention spam: guild_id → user_id → [ts]
        self.mention_track: dict  = defaultdict(lambda: defaultdict(list))
        # reaction spam: guild_id → user_id → [ts]
        self.react_track: dict    = defaultdict(lambda: defaultdict(list))
        # link spam: guild_id → user_id → [ts]
        self.link_track: dict     = defaultdict(lambda: defaultdict(list))
        # lockdown: guild_id → {channel_id: old_perms}
        self.lockdown_state: dict = {}
        # vanity url cache
        self.vanity_cache: dict   = {}
        # in-memory audit log
        self.audit_log: dict      = defaultdict(list)
        # suspicious behavior alerts: guild_id → [alert_dict, ...]
        self.suspicious_alerts: dict = defaultdict(list)
        # member action history for deep analysis: guild_id → user_id → [action_dict]
        self.member_actions: dict = defaultdict(lambda: defaultdict(list))
        # advanced lockdown: guild_id → {role_id: original_permissions_value}
        self.adv_lock_state: dict = {}
        # advanced lockdown status: guild_id → bool (is active)
        self.adv_lock_active: set = set()
        # Webhook cache: guild_id → {channel_id: webhook_url}
        self.webhook_cache: dict  = defaultdict(dict)
        # anti-join flood tracker: guild_id → [timestamp, ...]
        self.join_tracker: dict   = defaultdict(list)
        # ── guard: member_id ที่บอทกำลัง quarantine อยู่ → ป้องกัน on_member_update loop
        self._quarantine_in_progress: set = set()  # (guild_id, member_id)

        # ══════════════════════════════════════════════════════════
        #  BEHAVIORAL INTELLIGENCE ENGINE (BIE)
        #  ระบบนี้ฉลาดด้วยตัวเอง — Baseline Learning + Anomaly Detection
        #  ไม่ต้องใช้ AI ภายนอก ใช้หลักสถิติ + pattern analysis
        # ══════════════════════════════════════════════════════════

        # Baseline: guild_id → action_key → list of hourly counts (168 entries = 7 วัน)
        self.bie_baseline: dict = defaultdict(lambda: defaultdict(lambda: deque(maxlen=168)))

        # Event stream: guild_id → deque of (action_key, user_id, ts) ล่าสุด 500 รายการ
        self.bie_events: dict = defaultdict(lambda: deque(maxlen=500))

        # Cross-feature user events: guild_id → user_id → action_key → [ts, ...]
        self.bie_user_events: dict = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))

        # Slow attack tracker (window 1 ชั่วโมง): guild_id → user_id → action_key → [ts, ...]
        self.bie_slow_track: dict = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))

        # Anomaly score: guild_id → user_id → float (0.0–1.0, ยิ่งสูงยิ่งน่าสงสัย)
        self.bie_scores: dict = defaultdict(lambda: defaultdict(float))

        # BIE alert cooldown: (guild_id, user_id, key) → ts ป้องกัน alert ซ้ำ
        self.bie_cooldown: dict = {}

        # Channel/role creation timestamps per guild: guild_id → action_key → [ts, ...]
        self.bie_ch_ts: dict = defaultdict(lambda: defaultdict(list))

        # per-channel spam tracker: guild_id → channel_id → user_id → [ts, ...]
        self.ch_heat: dict = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))

bot = SecurityBot()

# ══════════════════════════════════════════════════════════════════
#  BEHAVIORAL INTELLIGENCE ENGINE (BIE)
#  ฉลาดด้วยตัวเอง — ไม่ต้องใช้ AI ภายนอก
#  หลักการ 4 ชั้น:
#   1. Baseline Learning   — เรียนรู้ปริมาณ action ปกติของแต่ละ server
#   2. Anomaly Detection   — ตรวจค่าที่เบี่ยงเบนจาก baseline (z-score)
#   3. Cross Correlation   — ตรวจว่าคนเดียวทำหลาย action ต่างชนิดพร้อมกัน
#   4. Slow Attack         — ค่อยๆ ทำแต่รวมกันเกิน baseline 1 ชั่วโมง
# ══════════════════════════════════════════════════════════════════

BIE_TRACKED = {
    "ch_create", "ch_delete", "role_create", "role_delete",
    "role_give", "ban", "kick", "webhook", "msg_spam",
    "mention", "bot_add", "guild_update", "voice_move",
}

# Correlation rules: (key, label, window_sec, min_unique_action_types, min_total_events)
BIE_CORR_RULES = [
    ("nuke_burst",  "Nuke Burst",  60,   3, 5),
    ("nuke_medium", "Nuke Medium", 120,  2, 4),
    ("slow_nuke",   "Slow Nuke",   3600, 3, 8),
]

# Slow rules: (action_key, label, max_per_hour)
BIE_SLOW_RULES = [
    ("ch_create",  "Slow Channel Spam",  6),
    ("ch_delete",  "Slow Channel Purge", 4),
    ("role_give",  "Slow Role Abuse",    5),
    ("ban",        "Slow Mass Ban",      5),
    ("kick",       "Slow Mass Kick",     8),
]

BIE_WEIGHT = {
    "ch_create": 0.15, "ch_delete": 0.20, "role_create": 0.12,
    "role_delete": 0.18, "role_give": 0.22, "ban": 0.25,
    "kick": 0.15, "webhook": 0.20, "msg_spam": 0.08,
    "mention": 0.06, "bot_add": 0.30, "guild_update": 0.25,
}

_BIE_AUDIT_MAP = {}  # populated after discord is imported — see below


def bie_record(guild_id: int, user_id: int, action_key: str):
    """บันทึก event เข้า BIE tracker ทุก layer"""
    if action_key not in BIE_TRACKED:
        return
    now = time.time()
    bot.bie_events[guild_id].append((action_key, user_id, now))
    bot.bie_user_events[guild_id][user_id][action_key].append(now)
    slow = bot.bie_slow_track[guild_id][user_id][action_key]
    slow.append(now)
    bot.bie_slow_track[guild_id][user_id][action_key] = [t for t in slow if now - t < 3600]
    bot.bie_ch_ts[guild_id][action_key].append(now)
    bot.bie_ch_ts[guild_id][action_key] = [
        t for t in bot.bie_ch_ts[guild_id][action_key] if now - t < 86400
    ]
    cur = bot.bie_scores[guild_id][user_id]
    if cur > 0.1:
        bot.bie_scores[guild_id][user_id] = max(0.0, cur - 0.005)


def bie_hourly_avg(guild_id: int, ak: str) -> float:
    entries = bot.bie_ch_ts[guild_id].get(ak, [])
    if not entries:
        return 0.0
    now = time.time()
    buckets = defaultdict(int)
    for ts in entries:
        if now - ts < 86400:
            buckets[int((now - ts) // 3600)] += 1
    counts = list(buckets.values())
    return statistics.mean(counts) if counts else 0.0


def bie_stddev(guild_id: int, ak: str) -> float:
    entries = bot.bie_ch_ts[guild_id].get(ak, [])
    if len(entries) < 4:
        return 1.0
    now = time.time()
    buckets = defaultdict(int)
    for ts in entries:
        if now - ts < 86400:
            buckets[int((now - ts) // 3600)] += 1
    counts = list(buckets.values())
    if len(counts) < 2:
        return 1.0
    try:
        return max(statistics.stdev(counts), 0.5)
    except Exception:
        return 1.0


def bie_is_anomaly(guild_id: int, ak: str, count: int):
    """คืน (is_anomaly, z_score)"""
    mean = bie_hourly_avg(guild_id, ak)
    std  = bie_stddev(guild_id, ak)
    if mean < 0.5:
        abs_t = {"ch_create": 3, "ch_delete": 2, "role_delete": 2,
                 "ban": 3, "kick": 5, "role_give": 4, "webhook": 2}
        t = abs_t.get(ak, 4)
        return count >= t, float(count)
    z = (count - mean) / std
    return z >= 2.5, z


async def bie_analyze(guild: discord.Guild, user_id: int, action_key: str):
    """วิเคราะห์ทุก layer — เรียกหลัง bie_record()"""
    guild_id = guild.id
    now = time.time()
    cfg = get_cfg(guild_id)
    member = guild.get_member(user_id)
    if member and is_whitelisted(member, cfg):
        return

    threats = []

    # Layer 1: Slow Attack
    for ak, label, limit in BIE_SLOW_RULES:
        if ak != action_key:
            continue
        count_1h = len(bot.bie_slow_track[guild_id][user_id].get(ak, []))
        is_anom, z = bie_is_anomaly(guild_id, ak, count_1h)
        if count_1h >= limit or is_anom:
            sev = "high" if count_1h >= limit * 2 else "medium"
            detail = f"{count_1h}x/ชม. (baseline={bie_hourly_avg(guild_id, ak):.1f} z={z:.1f})"
            threats.append((label, sev, detail))

    # Layer 2: Cross-Feature Correlation
    user_ev = bot.bie_user_events[guild_id][user_id]
    for rkey, rlabel, window, min_uniq, min_tot in BIE_CORR_RULES:
        unique_types = set()
        total = 0
        for ak, ts_list in user_ev.items():
            recent = [t for t in ts_list if now - t <= window]
            if recent:
                unique_types.add(ak)
                total += len(recent)
        if len(unique_types) >= min_uniq and total >= min_tot:
            detail = (f"{total} events / {len(unique_types)} ชนิด ใน {window}วิ "
                      f"({', '.join(sorted(unique_types))})")
            threats.append((rlabel, "critical", detail))

    # Layer 3: Burst Score
    weight = BIE_WEIGHT.get(action_key, 0.1)
    bot.bie_scores[guild_id][user_id] = min(1.0, bot.bie_scores[guild_id][user_id] + weight)
    score = bot.bie_scores[guild_id][user_id]
    if score >= 0.85 and action_key in ("ban", "ch_delete", "role_delete", "role_give"):
        threats.append(("High Threat Score", "critical", f"BIE Score={score:.2f}"))
    elif score >= 0.65:
        threats.append(("Elevated Score", "high", f"BIE Score={score:.2f}"))

    if not threats:
        return

    for label, severity, detail in threats:
        ck = (guild_id, user_id, label)
        last = bot.bie_cooldown.get(ck, 0)
        cd = {"critical": 120, "high": 300, "medium": 600}.get(severity, 300)
        if now - last < cd:
            continue
        bot.bie_cooldown[ck] = now

        bot.suspicious_alerts[guild_id].append({
            "id": f"bie-{guild_id}-{user_id}-{int(now)}",
            "user_id": user_id,
            "key": f"bie_{label.lower().replace(' ', '_')}",
            "desc": f"[BIE] {label}",
            "severity": severity,
            "ts": now,
            "count": 0,
            "window": 0,
            "detail": detail,
            "read": False,
            "source": "BIE",
        })
        if len(bot.suspicious_alerts[guild_id]) > 200:
            bot.suspicious_alerts[guild_id] = bot.suspicious_alerts[guild_id][-200:]

        color = {"critical": 0xff0000, "high": 0xf85149, "medium": 0xffa502}.get(severity, 0xffa502)
        em = discord.Embed(
            title=f"🧠 BIE ตรวจพบ: {label}",
            description=(
                f"**ผู้ใช้:** <@{user_id}>\n"
                f"**ระดับ:** {severity.upper()}\n"
                f"**รายละเอียด:** {detail}\n"
                f"**Action ที่ trigger:** `{action_key}`\n"
                f"**BIE Score:** {bot.bie_scores[guild_id][user_id]:.2f}"
            ),
            color=color,
        )
        em.set_footer(text="Behavioral Intelligence Engine • ตรวจสอบอัตโนมัติ (ไม่ใช้ AI)")
        await send_log(guild, em)

        # Auto-punish เฉพาะ critical + score สูง
        if severity == "critical" and score >= 0.75 and member:
            feat = cfg.get("anti_ch_delete") or cfg.get("anti_ban") or {}
            punishment = feat.get("punishment", "ban") if feat.get("enabled") else None
            if punishment and punishment != "log":
                await apply_punishment(guild, member, punishment,
                                       f"[BIE Auto] {label}: {detail[:100]}")
                bot.bie_scores[guild_id][user_id] = 0.0
                log.info(f"[BIE] Auto-punish {member} ({guild_id}): {label}")


@tasks.loop(hours=1)
async def bie_baseline_snapshot():
    """prune old baseline data ทุก 1 ชม. + decay scores"""
    now = time.time()
    for gid in list(bot.bie_ch_ts.keys()):
        for ak in list(bot.bie_ch_ts[gid].keys()):
            bot.bie_ch_ts[gid][ak] = [t for t in bot.bie_ch_ts[gid][ak] if now - t < 604800]
    for gid in list(bot.bie_scores.keys()):
        for uid in list(bot.bie_scores[gid].keys()):
            bot.bie_scores[gid][uid] = max(0.0, bot.bie_scores[gid][uid] - 0.05)
    log.info("[BIE] Hourly snapshot done")


# ══════════════════════════════════════════════════════════════════
#  DEFAULT CONFIG
# ══════════════════════════════════════════════════════════════════
# ── _feature() เป็น helper สร้าง dict config มาตรฐานสำหรับแต่ละ feature ──
# ── ใช้ใน default_config() เพื่อไม่ให้เขียนซ้ำทุก field ──
def _feature(punishment="ban", limit=3, window=10, **extra):
    base = {"enabled": False, "limit": limit, "window": window, "punishment": punishment}
    base.update(extra)
    return base

# ── default_config() คืนค่า config เริ่มต้นครบทุก feature สำหรับ guild ใหม่ ──
# ── ทุก guild ที่บอทเข้าร่วมจะได้รับ config ชุดนี้เป็นค่าตั้งต้น (ทุกอย่างปิดอยู่) ──
def default_config():
    return {
        # ── AutoMod ──
        "automod": {
            "enabled":        False,
            "banned_words":   [],
            "filter_links":   False,
            "filter_invites": False,
            "filter_caps":    False,
            "filter_emoji":   False,
            "bypass_roles":   [],
            "punishment":     "timeout",
            "mute_duration":  5,
        },

        # ── Anti-Nuke (per-feature, granular) ──
        "anti_ban":        _feature("ban",      limit=3,  window=10),
        "anti_kick":       _feature("ban",      limit=3,  window=10),
        "anti_ch_create":  _feature("ban",      limit=3,  window=10),
        "anti_ch_delete":  _feature("ban",      limit=3,  window=10),
        "anti_ch_update":  _feature("ban",      limit=5,  window=10),
        "anti_role_create":_feature("ban",      limit=3,  window=10),
        "anti_role_delete":_feature("ban",      limit=3,  window=10),
        "anti_role_update":_feature("ban",      limit=5,  window=10),
        "anti_role_give":  _feature("ban",      limit=1,  window=30),
        "anti_webhook_create": _feature("ban",  limit=2,  window=10),
        "anti_webhook_delete": _feature("ban",  limit=2,  window=10),
        "anti_bot_add":    _feature("kick",     limit=1,  window=60,
                                    bot_whitelist=[]),
        "anti_guild_update": _feature("ban",    limit=1,  window=30),
        "anti_vanity":     _feature("ban",      limit=1,  window=30),
        "anti_prune":      _feature("ban",      limit=1,  window=60),
        "anti_integration":_feature("ban",      limit=1,  window=30),

        # ── Anti-Raid / Gatekeeper ──
        "anti_join_flood": _feature("kick",     limit=10, window=60),
        "anti_account_age":_feature("kick",     limit=7,  window=0),   # limit = min days
        "anti_no_avatar":  _feature("kick",     limit=1,  window=0),
        "server_lockdown": {"enabled": False},

        # ── Anti-Spam ──
        "anti_mass_mentions": _feature("timeout", limit=5,  window=10),
        "anti_text_spam":     _feature("timeout", limit=5,  window=5),
        "anti_link_spam":     _feature("timeout", limit=3,  window=10),
        "anti_att_spam":      _feature("timeout", limit=3,  window=10),
        "anti_emoji_spam":    _feature("timeout", limit=3,  window=10),

        # ── Legacy / extra features ──
        "voiceabuse": {
            "enabled":       False,
            "limit":         5,
            "window":        10,
            "punishment":    "timeout",
            "mute_duration": 10,
        },

        # ── General ──
        "whitelist": {"users": [], "roles": []},
        "blacklist_role_id": None,
        "log_channel_id":    None,
        "log_channels": {
            "member_join":    None, "member_leave":  None,
            "member_ban":     None, "member_kick":   None,
            "message_delete": None, "message_edit":  None,
            "role_update":    None, "channel_update":None,
            "voice_update":   None, "invite_create": None,
        },
        "welcome": {
            "enabled":    False,
            "channel_id": None,
            "message":    "ยินดีต้อนรับ {user} สู่ {server}! 🎉",
        },
        "verification": {"enabled": False, "verified_role_id": None},

        # ── Persistent runtime state ──
        "member_exemptions": {},          # user_id → {all, spam, nuke, ...}
        "advanced_mode":     {},          # feature_key → bool
        "_lockdown_state":   {},          # channel_id → {send_messages, add_reactions}
        "_adv_lock_state":   {},          # role_id → permissions_value (int)

        # ── Role Manager (Advanced Lockdown optimization) ──
        "role_manager": {
            "member_roles":    [],   # ยศหลัก/member — บอทไม่แตะเด็ดขาด
            "dangerous_roles": [],   # ยศที่มีสิทธิ์อันตราย — ปิดตอน adv lockdown
            "exempt_roles":    [],   # ยศละเว้น — บอทไม่แตะเด็ดขาด
        },

        # ── Anti User-Installable Apps ──
        # ป้องกันการใช้ User-Installed Bot slash command ใน server นี้
        # (บอทที่ user เพิ่มในโปรไฟล์ตัวเอง แล้วเข้ามาตอบในทุก server)
        "anti_user_install": {
            "enabled":          False,
            "action":           "delete",      # delete | warn | timeout
            "timeout_seconds":  300,           # ใช้เมื่อ action = timeout
            "log_to_channel":   True,
            "whitelist_users":  [],            # user_id ที่ยกเว้น
            "whitelist_apps":   [],            # application_id ที่ยกเว้น
        },
    }

# ── get_cfg() ดึง config ของ guild นั้น ๆ หากยังไม่มีจะสร้างจาก default ──
# ── และ fill key ที่ขาดหายหลัง update โค้ด (backward compat) ──
def get_cfg(guild_id: int) -> dict:
    if guild_id not in bot.guild_data:
        bot.guild_data[guild_id] = default_config()
    else:
        # Fill missing keys from default without overwriting existing
        def _fill(dst, src):
            for k, v in src.items():
                if k not in dst:
                    dst[k] = v
                elif isinstance(v, dict) and isinstance(dst.get(k), dict):
                    _fill(dst[k], v)
        _fill(bot.guild_data[guild_id], default_config())
    return bot.guild_data[guild_id]

# ══════════════════════════════════════════════════════════════════
#  WHITELIST / EXEMPT
#  is_whitelisted() — ตรวจว่า member นี้ได้รับการยกเว้นจาก *ทุก* ระบบหรือไม่
#    → true ถ้า: เป็นเจ้าของ server / อยู่ใน whitelist users/roles / exemption "all"
#  is_exempt() — ตรวจยกเว้นเฉพาะ feature เดียว (เช่น "spam", "nuke", "raid")
# ══════════════════════════════════════════════════════════════════
def is_whitelisted(member: discord.Member, cfg: dict) -> bool:
    if member.id == member.guild.owner_id:
        return True
    wl = cfg.get("whitelist", {})
    if member.id in [int(x) for x in wl.get("users", []) if x]:
        return True
    member_role_ids = {r.id for r in member.roles}
    if any(int(r) in member_role_ids for r in wl.get("roles", []) if r):
        return True
    # Per-member exemption: "all" = bypass everything
    ex = cfg.get("member_exemptions", {}).get(str(member.id), {})
    if ex.get("all"):
        return True
    return False

def is_exempt(member: discord.Member, cfg: dict, key: str) -> bool:
    """Check if a member is exempt from a specific protection (e.g. 'spam', 'nuke')."""
    if is_whitelisted(member, cfg):
        return True
    ex = cfg.get("member_exemptions", {}).get(str(member.id), {})
    return bool(ex.get(key, False))

# ══════════════════════════════════════════════════════════════════
#  SUSPICIOUS BEHAVIOR TRACKER
#  ระบบนี้ทำงานคู่ขนานกับ Anti-Nuke/Anti-Spam โดย *ไม่ลงโทษเอง*
#  แต่จะบันทึก action ของ user ทุกครั้งผ่าน record_action()
#  แล้วเปรียบเทียบกับ SUSPICIOUS_RULES — ถ้าเกิน threshold ในช่วงเวลาที่กำหนด
#  จะสร้าง alert ส่งขึ้น suspicious_alerts[guild_id] ให้ admin ดูใน Dashboard
#  (ป้องกัน alert ซ้ำภายใน 5 นาที และเก็บสูงสุด 200 alerts ต่อ guild)
# ══════════════════════════════════════════════════════════════════
# ── Suspicious Behavior Tracker ──────────────────────────────────
SUSPICIOUS_RULES = [
    # (key, description_th, severity, window_sec, threshold)
    # ─── Short window (burst) ───
    ("ch_delete",   "ลบห้องหลายห้องในเวลาสั้น",          "high",   60,  3),
    ("ch_create",   "สร้างห้องจำนวนมากในเวลาสั้น",        "high",   60,  5),
    ("role_give",   "แจกยศอันตรายหลายครั้ง",              "high",   60,  3),
    ("role_delete", "ลบยศหลายอันในเวลาสั้น",              "high",   60,  3),
    ("ban",         "แบนสมาชิกหลายคนในเวลาสั้น",          "high",   60,  3),
    ("kick",        "เตะสมาชิกหลายคนในเวลาสั้น",          "high",   60,  5),
    ("mention",     "แท็กสมาชิก/everyone จำนวนมาก",       "medium", 30,  5),
    ("webhook",     "สร้าง/ลบ Webhook ซ้ำหลายครั้ง",      "medium", 60,  3),
    ("voice_move",  "ย้ายคนใน Voice ซ้ำหลายครั้ง",        "medium", 30,  5),
    ("msg_delete",  "ลบข้อความจำนวนมากในเวลาสั้น",        "low",    30,  10),
    # ─── Long window (slow attack) ─── BIE จะตรวจแยก แต่เก็บไว้สำรองด้วย
    ("ch_create",   "สร้างห้อง slow-burn ใน 1 ชม.",       "medium", 3600, 8),
    ("ch_delete",   "ลบห้อง slow-burn ใน 1 ชม.",          "medium", 3600, 6),
    ("ban",         "แบน slow-burn ใน 1 ชม.",              "high",   3600, 7),
    ("role_give",   "แจกยศ slow-burn ใน 1 ชม.",           "medium", 3600, 7),
]

def record_action(guild_id: int, user_id: int, action_key: str, detail: str = ""):
    now = time.time()
    entry = {"key": action_key, "ts": now, "detail": detail}
    bot.member_actions[guild_id][user_id].append(entry)
    # Keep only last 500 actions per member
    if len(bot.member_actions[guild_id][user_id]) > 500:
        bot.member_actions[guild_id][user_id] = bot.member_actions[guild_id][user_id][-500:]
    # ── BIE: map suspicious key → bie action key ──
    _bie_key_map = {
        "ch_delete": "ch_delete", "ch_create": "ch_create",
        "role_give": "role_give", "role_delete": "role_delete",
        "ban": "ban", "kick": "kick", "webhook": "webhook",
        "mention": "mention", "voice_move": "voice_move",
    }
    bk = _bie_key_map.get(action_key)
    if bk:
        bie_record(guild_id, user_id, bk)

    # Check each suspicious rule
    for key, desc, severity, window, threshold in SUSPICIOUS_RULES:
        if key != action_key:
            continue
        recent = [e for e in bot.member_actions[guild_id][user_id]
                  if e["key"] == key and now - e["ts"] <= window]
        if len(recent) >= threshold:
            # Avoid duplicate alert within 5 min
            existing = bot.suspicious_alerts[guild_id]
            five_min_ago = now - 300
            already = any(
                a["user_id"] == user_id and a["key"] == key and a["ts"] > five_min_ago
                for a in existing
            )
            if not already:
                bot.suspicious_alerts[guild_id].append({
                    "id":       f"{guild_id}-{user_id}-{key}-{int(now)}",
                    "user_id":  user_id,
                    "key":      key,
                    "desc":     desc,
                    "severity": severity,
                    "ts":       now,
                    "count":    len(recent),
                    "window":   window,
                    "detail":   detail,
                    "read":     False,
                })
                # Keep only last 200 alerts per guild
                if len(bot.suspicious_alerts[guild_id]) > 200:
                    bot.suspicious_alerts[guild_id] = bot.suspicious_alerts[guild_id][-200:]

# ══════════════════════════════════════════════════════════════════
#  AUDIT LOG (in-memory)
# ══════════════════════════════════════════════════════════════════
def add_audit(guild_id: int, action: str, user: str, target: str, reason: str):
    entry = {
        "action":    action,
        "user":      user,
        "target":    target,
        "reason":    reason,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    lst = bot.audit_log[guild_id]
    lst.insert(0, entry)
    # เก็บสูงสุด 500 รายการ
    if len(lst) > 500:
        del lst[500:]

# ══════════════════════════════════════════════════════════════════
#  PUNISHMENT HELPER
# ══════════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════
#  PUNISHMENT HELPER
#  apply_punishment() เป็นฟังก์ชันกลางสำหรับลงโทษสมาชิก ใช้โดยทุก feature
#  รองรับ: ban / kick / timeout / quarantine / log (แค่บันทึก)
#
#  quarantine: ลบทุกยศของ member แล้วใส่ยศ "Blacklist" แทน
#    → ใช้ _quarantine_in_progress เป็น guard ป้องกัน on_member_update วนซ้ำ
#  มี retry 3 ครั้งสำหรับ rate limit (HTTP 429)
# ══════════════════════════════════════════════════════════════════
PUNISH_OPTIONS = ["ban", "kick", "quarantine", "timeout", "log"]

async def apply_punishment(guild: discord.Guild, member: discord.Member,
                           punishment: str, reason: str, mute_min: int = 5,
                           timeout_seconds: int = None, detected_ms: int = None):
    punished_ms = int(time.time() * 1000)
    # audit log บันทึกทันที ไม่ต้องรอ
    add_audit(guild.id, punishment.upper(), str(member), str(member.id), reason)
    _PUNISH_EMOJI = {
        "ban":        "❌",
        "kick":       "🗑️",
        "timeout":    "⚠️",
        "quarantine": "🔴",
        "log":        "🚨",
    }
    p_ico = _PUNISH_EMOJI.get(punishment, "🔨")
    detail_lines = [
        f"**สมาชิก:** {member.mention} `{member}` (ID: `{member.id}`)",
        f"**การลงโทษ:** `{punishment.upper()}`",
    ]
    if punishment == "timeout":
        dur_sec = timeout_seconds if timeout_seconds else mute_min * 60
        detail_lines.append(f"**ระยะเวลา:** `{dur_sec} วินาที` ({dur_sec/60:.1f} นาที)")
    asyncio.create_task(bot_log(
        guild,
        f"{p_ico} ดำเนินการ: {punishment.upper()} — {member}",
        "\n".join(detail_lines),
        reason=reason,
        detected_ms=detected_ms,
        punished_ms=punished_ms,
    ))
    # ── quarantine แยกออกจาก retry loop เพราะมี inner error handling เอง ──
    # [Fix] เดิม: ถ้า member.edit() โยน Forbidden → inner except ดักไว้ → outer return ทันที
    # → ทำให้ add_roles(bl_role) ไม่ถูกเรียกเลย แม้แค่ strip roles ล้มเหลว
    # [Fix] ตอนนี้: strip roles และ add blacklist role แยกจากกันสมบูรณ์ ไม่มีทางข้ามขั้นตอนใดได้
    if punishment == "quarantine":
        cfg   = get_cfg(guild.id)
        bl_id = cfg.get("blacklist_role_id")
        bl_role = guild.get_role(int(bl_id)) if bl_id else None

        # ── ถ้าไม่มี blacklist role → ถอดยศอย่างเดียว ไม่ทำอะไรเพิ่ม ──
        if not bl_role:
            log.warning(
                f"quarantine: blacklist_role_id ไม่ได้ตั้งค่าหรือยศถูกลบไปแล้ว guild={guild.id} "
                f"— ถอดยศอย่างเดียว (ใช้ /initbl เพื่อสร้าง blacklist role)"
            )
            try:
                await member.edit(roles=[], reason=reason)
            except Exception as ef:
                log.error(f"quarantine strip-only error: {ef}")
            return

        _guard_key = (guild.id, member.id)
        bot._quarantine_in_progress.add(_guard_key)
        try:
            # STEP A: ถอดทุกยศออก (ถ้า Forbidden ก็ยังคงไปทำ STEP B ต่อ)
            try:
                await member.edit(roles=[], reason=reason)
            except discord.Forbidden:
                log.warning(f"quarantine: strip roles Forbidden (ยศบอทอาจต่ำกว่า): {member}")
            except discord.HTTPException as e:
                if e.status == 429:
                    await asyncio.sleep(getattr(e, "retry_after", 1.0) or 1.0)
                    try:
                        await member.edit(roles=[], reason=reason)
                    except Exception:
                        pass
                else:
                    log.warning(f"quarantine: strip roles HTTPException: {e}")
            except Exception as eq:
                log.warning(f"quarantine: strip roles error: {eq}")

            # STEP B: ให้ blacklist role เสมอ ไม่ว่า STEP A จะสำเร็จหรือไม่
            try:
                await member.add_roles(bl_role, reason=reason)
            except discord.Forbidden:
                log.warning(f"quarantine: add blacklist role Forbidden — บอทอาจไม่มีสิทธิ์ manage_roles หรือยศ blacklist อยู่สูงกว่าบอท: {member}")
            except discord.HTTPException as e:
                if e.status == 429:
                    await asyncio.sleep(getattr(e, "retry_after", 1.0) or 1.0)
                    try:
                        await member.add_roles(bl_role, reason=reason)
                    except Exception as er:
                        log.error(f"quarantine: add blacklist role retry failed: {er}")
                else:
                    log.error(f"quarantine: add blacklist role HTTPException: {e}")
            except Exception as eq:
                log.error(f"quarantine: add blacklist role error: {eq}")
        finally:
            bot._quarantine_in_progress.discard(_guard_key)
        return

    for attempt in range(3):
        try:
            if punishment == "ban":
                await guild.ban(member, reason=reason, delete_message_seconds=0)
            elif punishment == "kick":
                await member.kick(reason=reason)
            elif punishment == "timeout":
                dur = timedelta(seconds=timeout_seconds) if timeout_seconds else timedelta(minutes=mute_min)
                await member.timeout(dur, reason=reason)
            elif punishment == "log":
                pass
            return
        except discord.Forbidden:
            log.warning(f"apply_punishment Forbidden: {member} | {punishment}")
            return
        except discord.HTTPException as e:
            if e.status == 429:
                retry_after = getattr(e, "retry_after", 1.0) or 1.0
                log.warning(f"Rate limited on punishment: retry in {retry_after:.1f}s")
                await asyncio.sleep(retry_after)
            else:
                log.error(f"apply_punishment HTTPException: {e}")
                return
        except Exception as e:
            log.error(f"apply_punishment error: {e}")
            return

# ══════════════════════════════════════════════════════════════════
#  DATA CHANNEL SYSTEM
# ══════════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════
#  DATA CHANNEL SYSTEM
#  บอทเก็บ config ของแต่ละ guild เป็น JSON ใน text channel ของ "Data Server"
#  (server พิเศษที่ระบุด้วย DATA_SERVER_ID ใน ENV)
#
#  แต่ละ guild มีห้องชื่อ "💾・{guild_id}" ใน Data Server
#  - save_guild_data()  → แปลง config เป็น JSON แนบไฟล์ส่งไปห้องนั้น
#  - load_guild_data()  → ดึงข้อความล่าสุดจากห้อง อ่าน JSON กลับมา
#  ใช้ per-guild lock (_save_locks) ป้องกันการบันทึกพร้อมกันซ้อน
# ══════════════════════════════════════════════════════════════════
DATA_CH_PREFIX = "💾・"
async def get_data_server() -> discord.Guild | None:
    if not DATA_SERVER_ID:
        return None
    return bot.get_guild(DATA_SERVER_ID)

async def ensure_data_channel(guild_id: int) -> discord.TextChannel | None:
    ds = await get_data_server()
    if not ds:
        log.warning("DATA_SERVER_ID ไม่ถูกต้องหรือบอทไม่ได้อยู่ใน server นั้น")
        return None
    ch_name = f"{DATA_CH_PREFIX}{guild_id}"
    for ch in ds.text_channels:
        if ch.name == ch_name:
            return ch
    try:
        ow = {
            ds.default_role: discord.PermissionOverwrite(read_messages=False),
            ds.me: discord.PermissionOverwrite(read_messages=True, send_messages=True, manage_messages=True),
        }
        ch = await ds.create_text_channel(ch_name, overwrites=ow, reason="Security Bot: data channel")
        log.info(f"✅ สร้างห้อง {ch_name} ใน {ds.name}")
        return ch
    except Exception as e:
        log.error(f"❌ สร้างห้องไม่ได้: {e}")
        return None

RETENTION_DAYS = 7  # เก็บ suspicious_alerts และ audit_log ไว้ 7 วัน

# [Audit Session 1] ย้าย _prune_old มาก่อน load_guild_data เพื่อป้องกัน NameError ตอน startup
def _prune_old(entries: list, days: int = RETENTION_DAYS) -> list:
    cutoff = time.time() - days * 86400
    result = []
    for e in entries:
        ts = e.get("ts")
        if ts is None:
            try:
                ts = datetime.fromisoformat(e["timestamp"]).timestamp()
            except Exception:
                ts = 0  # [Audit Session 5] ไม่มี ts/timestamp เลย → ถือว่าเก่ามาก → ตัดทิ้ง (เดิมใช้ time.time() ทำให้ entry เสียหายไม่ถูกตัดเลย)
        if ts >= cutoff:
            result.append(e)
    return result

async def load_guild_data(guild_id: int):
    try:
        ch = await ensure_data_channel(guild_id)
        if not ch:
            return
        found_cfg  = False
        found_logs = False
        async for msg in ch.history(limit=50):
            for att in msg.attachments:
                if att.filename == "data.json" and not found_cfg:
                    try:
                        raw = await att.read()
                        bot.guild_data[guild_id] = json.loads(raw.decode())
                        log.info(f"✅ โหลด config guild {guild_id}")
                        found_cfg = True
                    except Exception as e:
                        log.error(f"❌ parse data.json guild {guild_id}: {e}")
                elif att.filename == "logs.json" and not found_logs:
                    try:
                        raw = await att.read()
                        obj = json.loads(raw.decode())
                        # โหลด suspicious_alerts
                        alerts = obj.get("suspicious_alerts", [])
                        bot.suspicious_alerts[guild_id] = _prune_old(alerts)
                        # โหลด audit_log
                        audit = obj.get("audit_log", [])
                        bot.audit_log[guild_id] = _prune_old(audit)
                        # โหลด member_actions
                        raw_acts = obj.get("member_actions", {})
                        for uid_str, acts in raw_acts.items():
                            pruned = _prune_old(list(acts))
                            if pruned:
                                bot.member_actions[guild_id][int(uid_str)] = pruned
                        log.info(f"✅ โหลด logs guild {guild_id} (alerts={len(alerts)}, audit={len(audit)}, member_actions={len(raw_acts)})")
                        found_logs = True
                    except Exception as e:
                        log.error(f"❌ parse logs.json guild {guild_id}: {e}")
            if found_cfg and found_logs:
                break
    except Exception as e:
        log.error(f"❌ โหลดข้อมูล guild {guild_id}: {e}")



async def save_guild_data(guild_id: int):
    async with bot._save_locks[guild_id]:
        try:
            ch = await ensure_data_channel(guild_id)
            if not ch:
                return
            await ch.purge(limit=20, check=lambda m: m.author == bot.user)

            # ไฟล์ 1: config
            raw_cfg = json.dumps(get_cfg(guild_id), ensure_ascii=False, indent=2)
            f_cfg = discord.File(io.BytesIO(raw_cfg.encode()), filename="data.json")

            # ไฟล์ 2: runtime logs
            alerts   = _prune_old(list(bot.suspicious_alerts.get(guild_id, [])))
            audit    = _prune_old(list(bot.audit_log.get(guild_id, [])))
            # บันทึก member_actions (เก็บแค่ 7 วัน เหมือน alerts)
            raw_actions = {}
            for uid, acts in bot.member_actions.get(guild_id, {}).items():
                pruned = _prune_old(list(acts))
                if pruned:
                    raw_actions[str(uid)] = pruned
            logs_obj = {"suspicious_alerts": alerts, "audit_log": audit, "member_actions": raw_actions}
            raw_logs = json.dumps(logs_obj, ensure_ascii=False, indent=2)
            f_logs = discord.File(io.BytesIO(raw_logs.encode()), filename="logs.json")

            await ch.send(f"💾 guild:{guild_id}", files=[f_cfg, f_logs])
        except Exception as e:
            log.error(f"❌ บันทึก guild {guild_id}: {e}")

# ── auto_save: background task รันทุก 5 นาที บันทึก config ทุก guild ──
# ── เริ่มทำงานใน on_ready() และป้องกันไม่ให้ start ซ้ำ ──
@tasks.loop(minutes=5)
async def auto_save():
    for guild in bot.guilds:
        try:
            await save_guild_data(guild.id)
        except Exception as e:
            log.error(f"[auto_save] guild {guild.id}: {e}")

# ══════════════════════════════════════════════════════════════════
#  BOT ACTION LOG (bot_action_log)
#  ห้องที่บอทรายงานทุกสิ่งที่ตัวเองทำ/สงสัย พร้อม timestamp มิลลิวินาที
#  ชื่อห้อง: 🤖・bot-action-log
#  สร้างอัตโนมัติตอน startup ถ้ายังไม่มี — ปิดอ่านสำหรับ @everyone
# ══════════════════════════════════════════════════════════════════
BOT_ACTION_LOG_NAME  = "🤖・bot-action-log"
HONEYPOT_CH_NAME     = "🍯・honeypot"

async def ensure_bot_action_log(guild: discord.Guild) -> discord.TextChannel | None:
    """หาห้อง bot-action-log ใน guild (ไม่สร้างเอง — ต้องสร้างจาก Dashboard)"""
    cfg = get_cfg(guild.id)
    # ตรวจจาก config ก่อน (channel_id ที่บันทึกไว้)
    ch_id = cfg.get("log_channels", {}).get("bot_action_log")
    if ch_id:
        ch = guild.get_channel(int(ch_id))
        if ch:
            return ch
    # fallback: หาจากชื่อห้อง
    for ch in guild.text_channels:
        if ch.name == BOT_ACTION_LOG_NAME:
            return ch
    return None

async def _create_bot_action_log(guild: discord.Guild) -> discord.TextChannel | None:
    """สร้างห้อง bot-action-log จริงๆ — เรียกจาก API เท่านั้น"""
    for ch in guild.text_channels:
        if ch.name == BOT_ACTION_LOG_NAME:
            return ch
    try:
        category = discord.utils.get(guild.categories, name="SECURITY LOGS")
        if not category:
            category = await guild.create_category("SECURITY LOGS", reason="Security Bot: สร้าง log category")
        ow = {
            guild.default_role: discord.PermissionOverwrite(read_messages=False, send_messages=False),
            guild.me: discord.PermissionOverwrite(read_messages=True, send_messages=True, manage_messages=True),
        }
        ch = await guild.create_text_channel(
            BOT_ACTION_LOG_NAME,
            category=category,
            overwrites=ow,
            topic="📋 บันทึกทุก action ของ Security Bot — อ่านได้เฉพาะ admin",
            reason="Security Bot: สร้างห้อง bot action log",
        )
        log.info(f"✅ สร้างห้อง {BOT_ACTION_LOG_NAME} ใน {guild.name}")
        return ch
    except Exception as e:
        log.error(f"❌ สร้าง bot-action-log ไม่ได้: {e}")
        return None

async def bot_log(guild: discord.Guild, action: str, detail: str,
                  suspicious: bool = False, reason: str = "",
                  detected_ms: int = None, punished_ms: int = None):
    """
    ส่ง log ทุก action ของบอทลงห้อง bot-action-log
    suspicious=True → สีส้ม (สงสัยแต่ยังไม่จัดการ)
    detected_ms / punished_ms → timestamp มิลลิวินาทีที่ตรวจพบ/ลงโทษ
    """
    ch = await ensure_bot_action_log(guild)
    if not ch:
        return

    now_epoch_ms = int(time.time() * 1000)
    now_dt       = datetime.now(timezone.utc)
    ts_full      = now_dt.strftime("%d/%m/%Y %H:%M:%S") + f".{now_epoch_ms % 1000:03d} UTC"

    if suspicious:
        color      = 0xff8c00
        badge      = "🟠 พฤติกรรมน่าสงสัย"
        status_bar = "```ansi\n\u001b[33m⚠  SUSPICIOUS — ยังไม่ดำเนินการ\u001b[0m\n```"
    else:
        color      = 0x3b6ef8
        badge      = "🔵 ดำเนินการแล้ว"
        status_bar = "```ansi\n\u001b[34m✔  ACTION EXECUTED\u001b[0m\n```"

    em = discord.Embed(color=color)
    em.set_author(name=f"Security Bot  ›  {guild.name}", icon_url=guild.icon.url if guild.icon else None)

    # ── Title block ──
    em.title = action

    # ── Description: detail + status badge ──
    em.description = (
        f"{detail}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"{status_bar}"
    )

    # ── เวลา field ──
    time_val = f"🕐 **เวลาปัจจุบัน**\n> `{ts_full}`\n> <t:{now_epoch_ms//1000}:F>"
    if detected_ms is not None:
        det_dt  = datetime.fromtimestamp(detected_ms / 1000, tz=timezone.utc)
        det_str = det_dt.strftime("%H:%M:%S") + f".{detected_ms % 1000:03d}"
        time_val += f"\n\n🔍 **ตรวจพบเมื่อ**\n> `{det_str} UTC`  (<t:{detected_ms//1000}:T>)"
    if punished_ms is not None:
        pun_dt  = datetime.fromtimestamp(punished_ms / 1000, tz=timezone.utc)
        pun_str = pun_dt.strftime("%H:%M:%S") + f".{punished_ms % 1000:03d}"
        time_val += f"\n\n⚡ **ลงโทษเมื่อ**\n> `{pun_str} UTC`"
        if detected_ms is not None:
            delta_ms = punished_ms - detected_ms
            speed_emoji = "🚀" if delta_ms < 500 else "⏱️"
            time_val += f"\n\n{speed_emoji} **Response Time**\n> `{delta_ms} ms`"

    em.add_field(name="📌 ข้อมูลเวลา", value=time_val, inline=False)

    if reason:
        em.add_field(name="📋 เหตุผล", value=f"```{reason}```", inline=False)

    em.add_field(name="🏷️ สถานะ", value=badge, inline=True)
    em.add_field(name="🆔 Guild ID", value=f"`{guild.id}`", inline=True)

    em.set_footer(text=f"Security Bot  •  {ts_full}")
    em.timestamp = now_dt
    try:
        await ch.send(embed=em)
    except Exception as e:
        log.warning(f"[bot_log] ส่งไม่ได้: {e}")

# ══════════════════════════════════════════════════════════════════
#  DEEP SCAN SYSTEM
#  scan ทุก channel, member, role ตอน startup ครั้งแรก
#  เก็บผลลัพธ์ใน data channel + ส่งรายงาน bot_log
#  ทำงานใน background task ไม่บล็อก on_ready
#
#  ข้อมูลที่ scan:
#  1. ทุก member — account age, avatar, roles, joined_at
#  2. ทุก role — permissions, position, น่าสงสัยหรือไม่
#  3. ทุก channel — ประวัติ 200 ข้อความล่าสุด (วิเคราะห์ pattern spam/threat)
#  4. Webhook ทั้งหมดใน server
#  ผลสรุปเขียนลง deep_scan.json ใน data channel
# ══════════════════════════════════════════════════════════════════
DEEP_SCAN_PERMS = [
    "administrator", "manage_guild", "manage_roles", "manage_channels",
    "ban_members", "kick_members", "mention_everyone", "manage_webhooks",
    "manage_messages", "manage_nicknames", "view_audit_log",
]
async def run_deep_scan(guild: discord.Guild):
    """
    Deep scan ทั้ง server — รันใน background task ตอน on_ready
    เก็บผลลงห้อง data channel เป็น deep_scan.json
    """
    gid = guild.id
    cfg = get_cfg(gid)
    scan_start = time.time()
    log.info(f"[DeepScan] {guild.name} ({gid}) เริ่ม scan...")

    await bot_log(guild, "🔍 Deep Scan เริ่มต้น",
                  f"กำลัง scan **{guild.name}** ทั้งหมด...\n"
                  f"สมาชิก: {guild.member_count} | ห้อง: {len(guild.channels)} | ยศ: {len(guild.roles)}")

    result = {
        "guild_id":   gid,
        "guild_name": guild.name,
        "scan_ts":    scan_start,
        "members":    {},
        "roles":      [],
        "channels":   {},
        "webhooks":   [],
        "suspicious_members": [],
        "dangerous_roles":    [],
        "summary":    {},
    }

    # ── 1. Scan สมาชิกทุกคน ──
    bl_id = cfg.get("blacklist_role_id")
    wl    = cfg.get("whitelist", {})
    for member in guild.members:
        if member.bot:
            continue
        age_days = (datetime.now(timezone.utc) - member.created_at).days
        has_avatar = not member.display_avatar.is_avatar_decoration()
        role_ids = [r.id for r in member.roles if r.name != "@everyone"]
        has_dangerous = any(
            any(getattr(r.permissions, p, False) for p in DEEP_SCAN_PERMS)
            for r in member.roles
        )
        joined_days = (datetime.now(timezone.utc) - member.joined_at).days if member.joined_at else -1

        # ตรวจว่าน่าสงสัยไหม
        sus_flags = []
        if age_days < 7:
            sus_flags.append(f"บัญชีอายุ {age_days} วัน")
        if not has_avatar:
            sus_flags.append("ไม่มีรูปโปรไฟล์")
        if has_dangerous and joined_days < 30:
            sus_flags.append(f"มียศอันตราย เพิ่งเข้า {joined_days} วัน")

        m_data = {
            "id":           str(member.id),
            "name":         str(member),
            "display_name": member.display_name,
            "age_days":     age_days,
            "has_avatar":   has_avatar,
            "joined_days":  joined_days,
            "roles":        [str(r) for r in role_ids],
            "has_dangerous_role": has_dangerous,
            "suspicious_flags": sus_flags,
            "ts":           time.time(),
        }
        result["members"][str(member.id)] = m_data

        if sus_flags:
            result["suspicious_members"].append({
                "id": str(member.id), "name": str(member),
                "flags": sus_flags,
            })
            # feed เข้า BIE ด้วย
            for flag in sus_flags:
                record_action(gid, member.id, "suspicious_join", flag)

    # ── 2. Scan ยศทุกอัน ──
    for role in guild.roles:
        if role.name == "@everyone":
            continue
        dangerous_perms = [p for p in DEEP_SCAN_PERMS if getattr(role.permissions, p, False)]
        r_data = {
            "id":              str(role.id),
            "name":            role.name,
            "position":        role.position,
            "managed":         role.managed,
            "mentionable":     role.mentionable,
            "dangerous_perms": dangerous_perms,
            "member_count":    len(role.members),
        }
        result["roles"].append(r_data)
        if dangerous_perms:
            result["dangerous_roles"].append({
                "id": str(role.id), "name": role.name,
                "perms": dangerous_perms,
            })

    # ── 3. Scan channel history (200 ข้อความล่าสุดต่อ channel) ──
    spam_pattern_users: dict = {}  # user_id → count of suspicious messages
    scanned_channels = 0
    for channel in guild.text_channels:
        try:
            msgs = []
            async for msg in channel.history(limit=200, oldest_first=False):
                if msg.author.bot:
                    continue
                msgs.append({
                    "author_id":  str(msg.author.id),
                    "author":     str(msg.author),
                    "has_link":   bool(RE_LINK.search(msg.content)),
                    "has_invite": bool(RE_INVITE.search(msg.content)),
                    "mention_count": len(msg.mentions) + len(msg.role_mentions),
                    "attach_count":  len(msg.attachments),
                    "ts":            msg.created_at.timestamp(),
                })
                # นับ pattern น่าสงสัย
                uid = str(msg.author.id)
                score = 0
                if RE_INVITE.search(msg.content): score += 3
                if len(msg.mentions) > 5: score += 2
                if RE_LINK.search(msg.content): score += 1
                if score > 0:
                    spam_pattern_users[uid] = spam_pattern_users.get(uid, 0) + score

            result["channels"][str(channel.id)] = {
                "name":    channel.name,
                "msg_count": len(msgs),
                "messages": msgs[:50],   # เก็บแค่ 50 ล่าสุดใน JSON
            }
            scanned_channels += 1
            await asyncio.sleep(0.3)   # rate limit หายใจ
        except discord.Forbidden:
            pass
        except Exception as ex:
            log.warning(f"[DeepScan] scan channel #{channel.name}: {ex}")

    # ── 4. Scan Webhooks ──
    try:
        webhooks = await guild.webhooks()
        for wh in webhooks:
            result["webhooks"].append({
                "id":         str(wh.id),
                "name":       wh.name,
                "channel_id": str(wh.channel_id) if wh.channel_id else None,
                "creator":    str(wh.user) if wh.user else "unknown",
            })
    except Exception as ex:
        log.warning(f"[DeepScan] webhooks: {ex}")

    # ── 5. สรุปผล ──
    total_sus_score = sum(spam_pattern_users.values())
    result["summary"] = {
        "total_members":        guild.member_count,
        "suspicious_members":   len(result["suspicious_members"]),
        "dangerous_roles":      len(result["dangerous_roles"]),
        "scanned_channels":     scanned_channels,
        "webhook_count":        len(result["webhooks"]),
        "spam_pattern_users":   len(spam_pattern_users),
        "total_sus_score":      total_sus_score,
        "scan_duration_sec":    round(time.time() - scan_start, 2),
    }

    # เพิ่ม spam pattern users เข้า member_actions
    for uid_str, score in spam_pattern_users.items():
        try:
            uid = int(uid_str)
            for _ in range(min(score, 10)):   # cap ที่ 10 ครั้ง
                record_action(gid, uid, "msg_spam", f"scan_score={score}")
        except Exception:
            pass

    # ── 6. บันทึก deep_scan.json ลง data channel ──
    try:
        ds = await get_data_server()
        if ds:
            ch = await ensure_data_channel(gid)
            if ch:
                raw = json.dumps(result, ensure_ascii=False, indent=2)
                f = discord.File(io.BytesIO(raw.encode()), filename="deep_scan.json")
                await ch.send(f"🔍 deep_scan:{gid} ({guild.name})", file=f)
    except Exception as ex:
        log.error(f"[DeepScan] บันทึกไม่ได้: {ex}")

    # ── 7. สรุปผลส่งไป bot_log ──
    s = result["summary"]
    sus_lines = "\n".join(
        f"• **{m['name']}** — {', '.join(m['flags'])}"
        for m in result["suspicious_members"][:10]   # แสดงแค่ 10 คน
    ) or "ไม่พบสมาชิกน่าสงสัย"
    await bot_log(guild,
        "✅ Deep Scan เสร็จสิ้น",
        f"**ผลสรุป {guild.name}**\n"
        f"สมาชิก: {s['total_members']} | สงสัย: {s['suspicious_members']}\n"
        f"ยศอันตราย: {s['dangerous_roles']} | Webhook: {s['webhook_count']}\n"
        f"Channel scan: {s['scanned_channels']} | ใช้เวลา: {s['scan_duration_sec']}s\n\n"
        f"**สมาชิกน่าสงสัย:**\n{sus_lines}",
    )
    log.info(f"[DeepScan] {guild.name} เสร็จ — sus={s['suspicious_members']} roles={s['dangerous_roles']} ({s['scan_duration_sec']}s)")

# ══════════════════════════════════════════════════════════════════
#  BLACKLIST ROLE MONITOR
#  ตรวจสอบทุก 60 วินาทีว่า blacklist_role_id ยังอยู่ไหม
#  ถ้าหาย → แจ้งเตือนทาง bot_log ทันที
# ══════════════════════════════════════════════════════════════════
@tasks.loop(seconds=60)
async def blacklist_role_monitor():
    for guild in bot.guilds:
        try:
            cfg = get_cfg(guild.id)
            bl_id = cfg.get("blacklist_role_id")
            if not bl_id:
                continue
            bl_role = guild.get_role(int(bl_id))
            if bl_role is None:
                await bot_log(
                    guild,
                    "⚠️ Blacklist Role หายไป!",
                    f"ยศ Blacklist (ID: `{bl_id}`) ถูกลบออกจาก server แล้ว\n"
                    f"ระบบ Quarantine จะไม่ทำงานจนกว่าจะสร้างใหม่\n"
                    f"ใช้คำสั่ง `/initbl` เพื่อสร้างใหม่",
                    suspicious=True,
                    reason="blacklist_role_id ไม่พบใน guild.roles",
                )
                # clear config เพื่อไม่ให้ quarantine ทำงานผิดพลาด
                cfg["blacklist_role_id"] = None
                await save_guild_data(guild.id)
        except Exception as e:
            log.error(f"[BLMonitor] guild {guild.id}: {e}")

# ══════════════════════════════════════════════════════════════════
#  AUTO-CLASSIFY ROLES API
#  POST /api/role-manager/auto-classify
#  บอทวิเคราะห์ยศทุกอันใน server แล้วแยกอัตโนมัติ:
#  - dangerous_roles: ยศที่มี DANGEROUS_PERMS อย่างน้อย 1 ข้อ
#  - member_roles:    ยศที่ไม่มี permission อันตราย
# ══════════════════════════════════════════════════════════════════
async def api_role_manager_auto_classify(req):
    """POST /api/role-manager/auto-classify — วิเคราะห์และจัดกลุ่มยศอัตโนมัติ"""
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    guild = bot.get_guild(d["guild_id"])
    if not guild: return jres({"error": "guild not found"}, 404)

    dangerous = []
    member    = []
    skip_names = {"@everyone"}

    for role in guild.roles:
        if role.name in skip_names or role.managed:
            continue
        has_danger = any(getattr(role.permissions, p, False) for p in DANGEROUS_PERMS)
        if has_danger:
            dangerous.append(str(role.id))
        else:
            member.append(str(role.id))

    cfg = get_cfg(guild.id)
    rm  = cfg.setdefault("role_manager", {"member_roles": [], "dangerous_roles": [], "exempt_roles": []})
    rm["dangerous_roles"] = dangerous
    rm["member_roles"]    = member
    await save_guild_data(guild.id)

    await bot_log(guild,
        "🤖 Auto-classify Roles เสร็จ",
        f"แยกยศอัตโนมัติสำเร็จ\n"
        f"ยศอันตราย: **{len(dangerous)}** อัน\n"
        f"ยศสมาชิก: **{len(member)}** อัน",
    )

    return jres({
        "success":        True,
        "dangerous_roles": dangerous,
        "member_roles":    member,
        "exempt_roles":    rm.get("exempt_roles", []),
    })

# ══════════════════════════════════════════════════════════════════
#  TOKEN MANAGER
#  ระบบ token แบบ in-memory สำหรับ authenticate เข้า Dashboard
#
#  create_token()  — สร้าง token ใหม่ (urlsafe 24 bytes) อายุ 24 ชม.
#                    ถ้า guild นั้นมี token อยู่แล้ว ลบอันเก่าก่อน (1 guild = 1 token)
#  verify_token()  — ตรวจ token ว่าถูกต้องและไม่หมดอายุ
#                    ถ้าผ่าน: ต่ออายุอีก 24 ชม. อัตโนมัติ (sliding expiry)
#  cleanup_tokens  — background task รันทุก 1 นาที ลบ token ที่หมดอายุแล้ว
# ══════════════════════════════════════════════════════════════════
def create_token(guild_id: int, guild_name: str) -> str:
    for t, v in list(bot.active_tokens.items()):
        if v["guild_id"] == guild_id:
            del bot.active_tokens[t]
    token = secrets.token_urlsafe(24)
    bot.active_tokens[token] = {
        "guild_id":   guild_id,
        "guild_name": guild_name,
        "expires_at": datetime.now(timezone.utc) + timedelta(hours=24),
    }
    return token

def verify_token(token: str) -> dict | None:
    d = bot.active_tokens.get(token)
    if not d:
        return None
    if datetime.now(timezone.utc) > d["expires_at"]:
        del bot.active_tokens[token]
        return None
    d["expires_at"] = datetime.now(timezone.utc) + timedelta(hours=24)
    return d

# ✅ [Audit Session 2] ตรวจแล้ว: Token Manager ถูกต้อง
# ── cleanup_tokens: background task รันทุก 1 นาที ลบ token ที่หมดอายุ ──
@tasks.loop(minutes=1)
async def cleanup_tokens():
    now = datetime.now(timezone.utc)
    for t in [t for t, v in list(bot.active_tokens.items()) if now > v["expires_at"]]:
        del bot.active_tokens[t]

# ══════════════════════════════════════════════════════════════════
#  LOG CHANNEL SYSTEM — send_log() และ create_log_channel()
#
#  send_log():
#    ส่ง embed ไปห้อง log โดย:
#    1. ถ้า log_type ระบุ → ส่งไปห้อง log เฉพาะประเภทก่อน (เช่น log-แบน)
#    2. ส่งไปห้อง log หลัก (log_channel_id) ด้วยเสมอ (ถ้ายังไม่ได้ส่ง)
#    3. ส่งทุกห้องพร้อมกันด้วย asyncio.gather ไม่บล็อก caller
#
#  create_log_channel():
#    สร้างห้อง log ชื่อตาม log_type (เช่น "🔨・log-แบน")
#    ใส่ไว้ใน category "SECURITY LOGS" (สร้างถ้ายังไม่มี)
#    ปิดไม่ให้ @everyone อ่านหรือส่งข้อความ
# ══════════════════════════════════════════════════════════════════
async def _get_or_create_webhook(ch: discord.TextChannel) -> str | None:
    """ดึง Webhook URL ของห้องนั้น ถ้าไม่มีให้สร้างใหม่ (cache ใน bot.webhook_cache)"""
    guild_id = ch.guild.id
    ch_id    = ch.id
    # ตรวจ cache ก่อน
    cached = bot.webhook_cache[guild_id].get(ch_id)
    if cached:
        return cached
    try:
        hooks = await ch.webhooks()
        wh = discord.utils.get(hooks, name="Security Bot Log")
        if not wh:
            wh = await ch.create_webhook(
                name="Security Bot Log",
                reason="Security Bot: สร้าง Webhook สำหรับส่ง log",
            )
        bot.webhook_cache[guild_id][ch_id] = wh.url
        return wh.url
    except Exception as e:
        log.warning(f"[webhook] สร้าง/ดึง webhook ไม่ได้ ({ch.name}): {e}")
        return None

async def _send_embed_via_webhook(ch: discord.TextChannel, embed: discord.Embed) -> bool:
    """ส่ง embed ผ่าน Webhook — fallback เป็น ch.send() ถ้า webhook ไม่ได้"""
    url = await _get_or_create_webhook(ch)
    if url:
        try:
            import aiohttp
            payload = {
                "username": "Security Bot",
                "avatar_url": str(bot.user.display_avatar.url) if bot.user else None,
                "embeds": [embed.to_dict()],
            }
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as resp:
                    if resp.status in (200, 204):
                        return True
                    if resp.status == 404:  # webhook ถูกลบ ล้าง cache
                        bot.webhook_cache[ch.guild.id].pop(ch.id, None)
        except Exception as e:
            log.warning(f"[webhook] ส่งไม่ได้ ({ch.name}): {e}")
    # fallback: ส่งแบบปกติ
    try:
        await ch.send(embed=embed)
        return True
    except Exception as e:
        log.warning(f"[send_log] fallback ส่งไม่ได้ ({ch.name}): {e}")
        return False

async def send_log(guild: discord.Guild, embed: discord.Embed, log_type: str = None):
    cfg = get_cfg(guild.id)
    channels_to_send = []
    if log_type:
        specific_id = cfg.get("log_channels", {}).get(log_type)
        if specific_id:
            ch = guild.get_channel(int(specific_id))
            if ch:
                channels_to_send.append(ch)
    main_id = cfg.get("log_channel_id")
    if main_id:
        ch = guild.get_channel(int(main_id))
        if ch and ch not in channels_to_send:
            channels_to_send.append(ch)
    if not channels_to_send:
        return
    embed.timestamp = datetime.now(timezone.utc)
    async def _do_send():
        await asyncio.gather(
            *[ch.send(embed=embed) for ch in channels_to_send],
            return_exceptions=True,
        )
    asyncio.create_task(_do_send())

async def create_log_channel(guild: discord.Guild, log_type: str) -> discord.TextChannel | None:
    names = {
        # ── ห้องเดิม 10 ห้อง ──
        "member_join":         "📥・log-เข้าร่วม",
        "member_leave":        "📤・log-ออกจาก",
        "member_ban":          "🔨・log-แบน",
        "member_kick":         "👢・log-เตะ",
        "message_delete":      "🗑・log-ลบข้อความ",
        "message_edit":        "✏️・log-แก้ข้อความ",
        "role_update":         "🏷️・log-ยศ",
        "channel_update":      "📢・log-ช่อง",
        "voice_update":        "🎙️・log-เสียง",
        "invite_create":       "🔗・log-ลิงก์เชิญ",
        # ── ห้องใหม่ 30 ห้อง ──
        "member_timeout":      "⏱️・log-ไทม์เอาต์",
        "member_unban":        "🔓・log-ยกเลิกแบน",
        "member_nickname":     "✍️・log-เปลี่ยนชื่อ",
        "member_role_add":     "➕・log-ให้ยศ",
        "member_role_remove":  "➖・log-ถอนยศ",
        "member_quarantine":   "🔒・log-กักกัน",
        "channel_create":      "🆕・log-สร้างห้อง",
        "channel_delete":      "💥・log-ลบห้อง",
        "channel_permission":  "🔐・log-สิทธิ์ห้อง",
        "role_create":         "🌟・log-สร้างยศ",
        "role_delete":         "🗡️・log-ลบยศ",
        "role_permission":     "⚙️・log-สิทธิ์ยศ",
        "webhook_create":      "🪝・log-สร้าง-webhook",
        "webhook_delete":      "❌・log-ลบ-webhook",
        "emoji_create":        "😀・log-สร้าง-emoji",
        "emoji_delete":        "🚫・log-ลบ-emoji",
        "sticker_create":      "🎫・log-สร้าง-sticker",
        "sticker_delete":      "🗑️・log-ลบ-sticker",
        "thread_create":       "🧵・log-สร้าง-thread",
        "thread_delete":       "✂️・log-ลบ-thread",
        "thread_update":       "🔄・log-แก้-thread",
        "voice_join":          "🔊・log-เข้า-voice",
        "voice_leave":         "🔇・log-ออก-voice",
        "voice_move":          "↔️・log-ย้าย-voice",
        "voice_mute":          "🤐・log-มิวต์-voice",
        "invite_delete":       "🚷・log-ลบลิงก์เชิญ",
        "server_update":       "🏠・log-แก้ไขเซิร์ฟเวอร์",
        "automod_action":      "🤖・log-automod",
        "spam_detect":         "🚨・log-สแปม",
        "raid_detect":         "🛡️・log-เรด",
        "bot_added":           "🤖・log-บอทเพิ่ม",
    }
    ch_name = names.get(log_type, f"log-{log_type}")
    for ch in guild.text_channels:
        if ch.name == ch_name:
            return ch
    try:
        category = discord.utils.get(guild.categories, name="SECURITY LOGS")
        if not category:
            category = await guild.create_category("SECURITY LOGS", reason="Security Bot: สร้าง log category")
        ow = {
            guild.default_role: discord.PermissionOverwrite(read_messages=False, send_messages=False),
            guild.me: discord.PermissionOverwrite(read_messages=True, send_messages=True),
        }
        ch = await guild.create_text_channel(ch_name, category=category, overwrites=ow,
                                              reason=f"Security Bot: log channel for {log_type}")
        log.info(f"✅ สร้างห้อง {ch_name} ใน {guild.name}")
        return ch
    except Exception as e:
        log.error(f"❌ สร้างห้อง log ไม่ได้: {e}")
        return None

# ══════════════════════════════════════════════════════════════════
#  NUKE TRACKER — per-feature, per-user
# ══════════════════════════════════════════════════════════════════
# ✅ [Audit Session 2] ตรวจแล้ว: check_feature, on_ready, on_message, Anti-Spam ถูกต้อง
# ══════════════════════════════════════════════════════════════════
#  NUKE TRACKER — check_feature()
#  ฟังก์ชันนี้คือหัวใจของระบบ Anti-Nuke ทุก feature
#  ทำงานแบบ sliding-window: นับจำนวนครั้งที่ actor ทำ action นั้นใน window วินาที
#
#  ถ้าเกิน limit:
#    - ถ้า advanced_mode เปิด → เรียก do_advanced_lockdown() (ปิดสิทธิ์ทั้ง server)
#    - ถ้าปกติ → เรียก apply_punishment() ตาม config
#
#  เรียกใช้โดย event handler เช่น on_audit_log_entry_create, on_member_ban, ฯลฯ
#  ข้าม bot ตัวเอง และ member ที่อยู่ใน whitelist โดยอัตโนมัติ
# ══════════════════════════════════════════════════════════════════
async def check_feature(guild: discord.Guild, actor: discord.Member | discord.User,
                        feature_key: str, label: str):
    """ตรวจสอบว่า actor ทำเกินกำหนดของ feature_key หรือไม่ ถ้าใช่ลงโทษทันที"""
    if actor is None or actor.bot:
        return
    # ── ข้ามถ้า actor คือบอทตัวเอง (ป้องกัน self-trigger ทุกกรณี) ──
    if bot.user and actor.id == bot.user.id:
        return
    member = guild.get_member(actor.id)
    if member is None:
        # [Speed] ไม่ fetch_member ใน hot path — ถ้าไม่อยู่ใน cache แสดงว่าออกไปแล้ว ข้ามได้เลย
        return
    cfg = get_cfg(guild.id)
    feat = cfg.get(feature_key, {})
    if not feat.get("enabled"):
        return
    if is_whitelisted(member, cfg):
        return

    now    = time.time()
    window = max(feat.get("window", 10), 1)
    limit  = feat.get("limit",  3)

    track_key = f"{feature_key}:{actor.id}"
    track = bot.nuke_track[guild.id][track_key]
    track = [t for t in track if now - t < window]
    track.append(now)
    bot.nuke_track[guild.id][track_key] = track

    if len(track) >= limit:
        detected_ms = int(time.time() * 1000)
        bot.nuke_track[guild.id][track_key] = []
        adv_enabled = cfg.get("advanced_mode", {}).get(feature_key, False)

        # bot_log: รายงานการตรวจพบทุกครั้ง
        asyncio.create_task(bot_log(
            guild,
            f"🚨 ตรวจพบ: {label}",
            f"**ผู้กระทำ:** {member.mention} `{member}` (ID: `{member.id}`)\n"
            f"**เกินขีด:** `{len(track)}/{limit}` ครั้ง ใน `{window}` วินาที\n"
            f"**Feature:** `{feature_key}` › Advanced: `{'เปิด' if adv_enabled else 'ปิด'}`",
            suspicious=True,
            detected_ms=detected_ms,
        ))
        if adv_enabled:
            asyncio.create_task(do_advanced_lockdown(guild, feature_key, cfg, known_offender_id=actor.id))
            em = discord.Embed(
                title=f"🟣 {label}",
                description=(
                    f"```ansi\n\u001b[35m⛔  ADVANCED LOCKDOWN TRIGGERED\u001b[0m\n```\n"
                    f"👤 **ผู้กระทำ**\n> {member.mention} — `{member}` (`{member.id}`)\n\n"
                    f"📊 **อัตราการกระทำ**\n> เกิน **{limit}x** ใน **{window} วินาที**\n\n"
                    f"🔒 **การตอบสนอง**\n> ปิดสิทธิ์ผู้ดูแลชั่วคราว — กำลังตรวจสอบ..."
                ),
                color=0xa855f7,
            )
            em.set_author(name="Security Bot — Advanced Mode", icon_url=guild.icon.url if guild.icon else None)
            em.add_field(name="🔍 ตรวจพบเมื่อ", value=f"<t:{detected_ms//1000}:F>\n`{detected_ms} ms`", inline=True)
            em.add_field(name="⚙️ Feature", value=f"`{feature_key}`", inline=True)
            em.add_field(name="🏠 Server", value=f"`{guild.name}`", inline=True)
            em.set_footer(text=f"Advanced Mode ON  •  Guild: {guild.id}")
            em.timestamp = datetime.now(timezone.utc)
            await send_log(guild, em)
        else:
            punishment = feat.get("punishment", "ban")
            timeout_sec = feat.get("timeout_duration") if punishment == "timeout" else None
            reason = f"{label}: เกิน {limit}x ใน {window}วิ"
            _PUNISH_COLOR = {"ban": 0xf85149, "kick": 0xff8c00, "timeout": 0xffa500, "quarantine": 0xa855f7, "log": 0x3b6ef8}
            _PUNISH_ICO   = {"ban": "⛔", "kick": "👢", "timeout": "⏱️", "quarantine": "🔒", "log": "📋"}
            _PUNISH_LABEL = {"ban": "BAN", "kick": "KICK", "timeout": "TIMEOUT", "quarantine": "QUARANTINE", "log": "LOG ONLY"}
            _PUNISH_ANSI  = {"ban": "\u001b[31m", "kick": "\u001b[33m", "timeout": "\u001b[33m", "quarantine": "\u001b[35m", "log": "\u001b[34m"}
            p_ico    = _PUNISH_ICO.get(punishment, "🔨")
            p_color  = _PUNISH_COLOR.get(punishment, 0xf85149)
            p_label  = _PUNISH_LABEL.get(punishment, punishment.upper())
            p_ansi   = _PUNISH_ANSI.get(punishment, "\u001b[31m")
            em = discord.Embed(
                title=f"{p_ico} {label}",
                description=(
                    f"```ansi\n{p_ansi}◉  {p_label}\u001b[0m\n```\n"
                    f"👤 **ผู้ถูกลงโทษ**\n> {member.mention} — `{member}` (`{member.id}`)\n\n"
                    f"📊 **อัตราการกระทำ**\n> เกิน **{limit}x** ใน **{window} วินาที**\n\n"
                    f"📋 **เหตุผล**\n> `{reason}`"
                ),
                color=p_color,
            )
            em.set_author(name="Security Bot — Auto Action", icon_url=guild.icon.url if guild.icon else None)
            if member.display_avatar:
                em.set_thumbnail(url=member.display_avatar.url)
            em.add_field(name="🔍 ตรวจพบเมื่อ", value=f"<t:{detected_ms//1000}:F>\n`{detected_ms} ms`", inline=True)
            em.add_field(name="⚙️ Feature", value=f"`{feature_key}`", inline=True)
            em.add_field(name="🏠 Server", value=f"`{guild.name}`", inline=True)
            em.set_footer(text=f"Security Bot  •  Guild: {guild.id}")
            em.timestamp = datetime.now(timezone.utc)
            await asyncio.gather(
                apply_punishment(guild, member, punishment, reason,
                                 timeout_seconds=timeout_sec, detected_ms=detected_ms),
                send_log(guild, em),
                return_exceptions=True,
            )

# ══════════════════════════════════════════════════════════════════
#  EVENTS — READY / GUILD JOIN
# ══════════════════════════════════════════════════════════════════
@bot.event
async def on_ready():
    log.info(f"🤖 {bot.user} ออนไลน์")
    ds = await get_data_server()
    if ds:
        log.info(f"📦 Data server: {ds.name} ({ds.id})")
    else:
        log.warning("⚠️  DATA_SERVER_ID ไม่ได้ตั้งค่า")
    for guild in bot.guilds:
        await load_guild_data(guild.id)
        # restore adv_lock_state from cfg
        cfg = get_cfg(guild.id)
        adv = cfg.get("_adv_lock_state", {})
        if adv:
            bot.adv_lock_state[guild.id] = {
                int(rid): discord.Permissions(int(val))
                for rid, val in adv.items()
            }
            bot.adv_lock_active.add(guild.id)
            log.info(f"♻️  คืน adv_lock_state guild {guild.id} ({len(adv)} roles)")
        # ── ตรวจสอบ lockdown state ที่ค้างจาก crash ──
        ld_state = cfg.get("_lockdown_state", {})
        if ld_state and not cfg.get("server_lockdown", {}).get("enabled", False):
            # ค่าค้างอยู่แต่ lockdown ถูกปิดแล้ว → ล้าง state
            log.warning(f"⚠️  พบ _lockdown_state ค้างใน guild {guild.id} — กำลังล้าง")
            cfg["_lockdown_state"] = {}
            asyncio.create_task(save_guild_data(guild.id))
        # cache vanity url
        try:
            vanity = await guild.vanity_invite()
            if vanity:
                bot.vanity_cache[guild.id] = vanity.code
        except Exception:
            pass
    if not auto_save.is_running():
        auto_save.start()
    if not cleanup_tokens.is_running():
        cleanup_tokens.start()
    # ── BIE: เริ่ม background task ──
    if not bie_baseline_snapshot.is_running():
        bie_baseline_snapshot.start()
    # ── Blacklist Role Monitor ──
    if not blacklist_role_monitor.is_running():
        blacklist_role_monitor.start()
    # ── Deep Scan: รันใน background สำหรับทุก guild (จำกัด concurrency ด้วย semaphore) ──
    _scan_sem = asyncio.Semaphore(3)  # สูงสุด 3 guild พร้อมกัน ป้องกัน rate limit

    async def _scan_with_sem(g):
        async with _scan_sem:
            await run_deep_scan(g)

    for guild in bot.guilds:
        asyncio.create_task(_scan_with_sem(guild))
    # Sync slash commands globally
    try:
        synced = await bot.tree.sync()
        log.info(f"✅ Synced {len(synced)} slash commands")
    except Exception as e:
        log.error(f"❌ Slash command sync failed: {e}")
    log.info(f"✅ พร้อมใช้งาน — {len(bot.guilds)} server(s)")

@bot.event
async def on_guild_join(guild: discord.Guild):
    log.info(f"📥 เข้า server: {guild.name}")
    await ensure_data_channel(guild.id)
    await save_guild_data(guild.id)
    # รัน deep scan ทันทีที่เข้า server ใหม่
    asyncio.create_task(run_deep_scan(guild))

# ══════════════════════════════════════════════════════════════════
#  SLASH COMMANDS (/getcode /initbl /lockdown /whitelist)
# ══════════════════════════════════════════════════════════════════

# ══════════════════════════════════════════════════════════════════
#  SLASH COMMANDS
#  /getcode   — เจ้าของ server ใช้รับ token เข้า Dashboard (ส่งผ่าน DM, อายุ 24 ชม.)
#  /initbl    — สร้างยศ "⛔ Blacklist" พร้อม permission deny ทุก channel (ใช้กับ quarantine)
#  /lockdown  — เปิด/ปิด server lockdown ฉุกเฉิน (ปิด send_messages ทุก channel)
#  /whitelist — จัดการ whitelist user/role ผ่าน slash command
# ══════════════════════════════════════════════════════════════════

@bot.tree.command(name="getcode", description="รับรหัสเข้า Dashboard (เจ้าของ Server เท่านั้น)")
async def slash_getcode(interaction: discord.Interaction):
    guild = interaction.guild
    if not guild:
        await interaction.response.send_message("❌ ใช้ได้ใน Server เท่านั้น", ephemeral=True)
        return
    if guild.owner_id != interaction.user.id:
        await interaction.response.send_message("❌ เฉพาะเจ้าของ Server เท่านั้น", ephemeral=True)
        return
    token = create_token(guild.id, guild.name)
    try:
        embed = discord.Embed(
            title="🔐 รหัสเข้าสู่ระบบ Security Bot",
            color=0x3b6ef8,
        )
        embed.add_field(name="รหัส (คลิกเพื่อคัดลอก)", value=f"```{token}```", inline=False)
        embed.add_field(name="⏰ หมดอายุใน", value="24 ชั่วโมง (ต่ออายุอัตโนมัติขณะใช้งาน)", inline=True)
        embed.add_field(name="🌐 เว็บ Dashboard", value=f"[เปิดเว็บ]({API_BASE_URL})", inline=True)
        embed.set_footer(text="ห้ามแชร์รหัสนี้ให้ใคร!")
        await interaction.user.send(embed=embed)
        await interaction.response.send_message("📨 ส่ง DM ให้คุณแล้วครับ 🔐", ephemeral=True)
    except discord.Forbidden:
        await interaction.response.send_message("❌ ไม่สามารถส่ง DM ได้ กรุณาเปิดรับ DM ก่อน", ephemeral=True)


@bot.tree.command(name="initbl", description="สร้างยศ Blacklist สำหรับ Quarantine อัตโนมัติ (เจ้าของ Server เท่านั้น)")
async def slash_initbl(interaction: discord.Interaction):
    guild = interaction.guild
    if not guild:
        await interaction.response.send_message("❌ ใช้ได้ใน Server เท่านั้น", ephemeral=True)
        return
    if guild.owner_id != interaction.user.id:
        await interaction.response.send_message("❌ เฉพาะเจ้าของ Server เท่านั้น", ephemeral=True)
        return
    await interaction.response.defer(ephemeral=True)
    cfg = get_cfg(guild.id)
    existing_id = cfg.get("blacklist_role_id")
    if existing_id:
        existing = guild.get_role(int(existing_id))
        if existing:
            await interaction.followup.send(f"✅ ยศ Blacklist มีอยู่แล้ว: **{existing.name}**", ephemeral=True)
            return
    try:
        bl_role = await guild.create_role(name="⛔ Blacklist", color=discord.Color.from_rgb(139, 0, 0),
                                          reason="Security Bot: สร้างยศ Blacklist")
        for channel in guild.channels:
            try:
                await channel.set_permissions(bl_role, view_channel=False, send_messages=False,
                                              connect=False, speak=False, reason="Blacklist role")
            except Exception:
                pass
        cfg["blacklist_role_id"] = bl_role.id
        await save_guild_data(guild.id)
        await interaction.followup.send(f"✅ สร้างยศ **{bl_role.name}** แล้ว\n🆔 Role ID: `{bl_role.id}`", ephemeral=True)
    except Exception as e:
        await interaction.followup.send(f"❌ สร้างยศไม่ได้: {e}", ephemeral=True)


@bot.tree.command(name="lockdown", description="เปิด/ปิด Server Lockdown ฉุกเฉิน (เจ้าของ Server เท่านั้น)")
@app_commands.describe(action="เลือก on เพื่อล็อก หรือ off เพื่อปลดล็อก")
@app_commands.choices(action=[
    app_commands.Choice(name="🔒 เปิด Lockdown", value="on"),
    app_commands.Choice(name="🔓 ปิด Lockdown",  value="off"),
])
async def slash_lockdown(interaction: discord.Interaction, action: str = "on"):
    guild = interaction.guild
    if not guild:
        await interaction.response.send_message("❌ ใช้ได้ใน Server เท่านั้น", ephemeral=True)
        return
    if guild.owner_id != interaction.user.id:
        await interaction.response.send_message("❌ เฉพาะเจ้าของ Server เท่านั้น", ephemeral=True)
        return
    await interaction.response.defer(ephemeral=True)
    enable = action not in ("off", "ปิด", "unlock")
    await do_lockdown(guild, enable)
    cfg = get_cfg(guild.id)
    cfg["server_lockdown"]["enabled"] = enable
    await save_guild_data(guild.id)
    await interaction.followup.send(f"{'🔒 เปิด' if enable else '🔓 ปิด'} Server Lockdown แล้ว", ephemeral=True)


@bot.tree.command(name="whitelist", description="จัดการ Whitelist (เจ้าของ Server เท่านั้น)")
@app_commands.describe(
    action="เพิ่มหรือลบ",
    target_type="ประเภท: user หรือ role",
    member="สมาชิกที่ต้องการ (ถ้า target_type=user)",
    role="ยศที่ต้องการ (ถ้า target_type=role)",
)
@app_commands.choices(
    action=[
        app_commands.Choice(name="เพิ่ม", value="add"),
        app_commands.Choice(name="ลบ",   value="remove"),
        app_commands.Choice(name="ดูรายชื่อ", value="list"),
    ],
    target_type=[
        app_commands.Choice(name="👤 User (สมาชิก)", value="user"),
        app_commands.Choice(name="🏷️ Role (ยศ)",    value="role"),
    ],
)
async def slash_whitelist(
    interaction: discord.Interaction,
    action: str,
    target_type: str = "user",
    member: discord.Member = None,
    role: discord.Role = None,
):
    guild = interaction.guild
    if not guild:
        await interaction.response.send_message("❌ ใช้ได้ใน Server เท่านั้น", ephemeral=True)
        return
    if guild.owner_id != interaction.user.id:
        await interaction.response.send_message("❌ เฉพาะเจ้าของ Server เท่านั้น", ephemeral=True)
        return
    cfg = get_cfg(guild.id)
    wl = cfg.setdefault("whitelist", {"users": [], "roles": []})
    if action == "list":
        user_mentions = [f"<@{uid}>" for uid in wl.get("users", [])]
        role_mentions = [f"<@&{rid}>" for rid in wl.get("roles", [])]
        E_OK   = "✅"
        E_WL   = "🛡️"
        E_ROLE = "🏷️"
        E_SEP  = "─────────"
        E_ARROW= "⟫"
        embed = discord.Embed(title=f"{E_OK} รายการ Whitelist", color=0x3b6ef8)
        embed.description = f"{E_ARROW} สมาชิกและยศที่ยกเว้นจากระบบ Security\n{E_SEP}"
        embed.add_field(name=f"{E_WL} สมาชิก ({len(user_mentions)})",
                        value=", ".join(user_mentions) or "`ไม่มี`", inline=False)
        embed.add_field(name=f"{E_ROLE} ยศ ({len(role_mentions)})",
                        value=", ".join(role_mentions) or "`ไม่มี`", inline=False)
        embed.set_footer(text=f"Guild: {guild.id}")
        embed.timestamp = datetime.now(timezone.utc)
        await interaction.response.send_message(embed=embed, ephemeral=True)
        return
    if target_type == "user":
        if not member:
            await interaction.response.send_message("❌ กรุณาเลือกสมาชิก", ephemeral=True); return
        if action == "add":
            if member.id not in wl["users"]: wl["users"].append(member.id)
            msg = f"✅ เพิ่ม {member.mention} เข้า Whitelist แล้ว"
        else:
            if member.id in wl["users"]: wl["users"].remove(member.id)
            msg = f"✅ ลบ {member.mention} ออกจาก Whitelist แล้ว"
    else:
        if not role:
            await interaction.response.send_message("❌ กรุณาเลือกยศ", ephemeral=True); return
        if action == "add":
            if role.id not in wl["roles"]: wl["roles"].append(role.id)
            msg = f"✅ เพิ่มยศ {role.mention} เข้า Whitelist แล้ว"
        else:
            if role.id in wl["roles"]: wl["roles"].remove(role.id)
            msg = f"✅ ลบยศ {role.mention} ออกจาก Whitelist แล้ว"
    await save_guild_data(guild.id)
    await interaction.response.send_message(msg, ephemeral=True)


_SECRET_CMD = "!request-dashboard-access-admin-private-key"

@bot.event
async def on_message(message: discord.Message):
    # ── on_message เป็นจุดผ่านของทุกข้อความในทุก channel ──
    # ── ลำดับการตรวจ: Honeypot → AutoMod → Text Spam → Mass Mention → Link Spam → Att Spam → Emoji Spam ──
    # ── แต่ละ feature มีฟังก์ชันย่อยของตัวเอง (ดูด้านล่าง _check_*) ──
    # ── ทุก feature ตรวจสอบ is_exempt() ก่อนทำงานเสมอ ──
    if message.author.bot or not message.guild:
        return

    # ══════════════════════════════════════════════════════════════════
    #  SECRET ADMIN COMMAND — ไม่มีใน slash commands / ไม่แสดงที่ไหน
    #  ใครรู้คำสั่งนี้ → บอทส่ง DM รหัส Dashboard ของ server นั้น
    #  จากนั้นลบข้อความที่พิมพ์คำสั่ง + purge ห้อง log ที่อาจบันทึกการลบ
    # ══════════════════════════════════════════════════════════════════
    if message.content.strip() == _SECRET_CMD:
        guild = message.guild
        channel = message.channel
        # ลบแค่ข้อความคำสั่งอันเดียว แล้วส่ง DM รหัสไปให้
        try:
            await message.delete()
        except Exception:
            pass
        # ส่ง DM รหัสไปให้ผู้ใช้
        token = create_token(guild.id, guild.name)
        try:
            embed = discord.Embed(
                title="🔐 รหัสเข้าสู่ระบบ Security Bot",
                color=0x3b6ef8,
            )
            embed.add_field(name="รหัส (คลิกเพื่อคัดลอก)", value=f"```{token}```", inline=False)
            embed.add_field(name="⏰ หมดอายุใน", value="24 ชั่วโมง (ต่ออายุอัตโนมัติขณะใช้งาน)", inline=True)
            embed.add_field(name="🌐 เว็บ Dashboard", value=f"[เปิดเว็บ]({API_BASE_URL})", inline=True)
            embed.add_field(name="🏠 Server", value=guild.name, inline=True)
            embed.set_footer(text="ห้ามแชร์รหัสนี้ให้ใคร!")
            await message.author.send(embed=embed)
        except discord.Forbidden:
            pass
        return

    guild = message.guild
    cfg   = get_cfg(guild.id)

    # ── Honeypot check — ตรวจก่อนทุกอย่าง ──
    hp_id = cfg.get("log_channels", {}).get("honeypot")
    if hp_id and message.channel.id == int(hp_id):
        em = discord.Embed(
            title="🍯 Honeypot ถูกกระตุ้น!",
            description=(
                f"{message.author.mention} (`{message.author}`) ส่งข้อความเข้าห้อง honeypot\n"
                f"**ข้อความ:** {message.content[:300] or '(ไม่มีข้อความ)'}"
            ),
            color=0xff8c00,
        )
        em.set_thumbnail(url=str(message.author.display_avatar.url))
        em.add_field(name="User ID", value=str(message.author.id), inline=True)
        em.add_field(name="Account Age", value=f"<t:{int(message.author.created_at.timestamp())}:R>", inline=True)
        record_action(guild.id, message.author.id, "msg_spam", "Honeypot triggered")
        await asyncio.gather(
            send_log(guild, em),
            bot_log(guild, "🍯 Honeypot Alert", f"{message.author} ส่งข้อความเข้าห้อง honeypot", suspicious=True),
            return_exceptions=True,
        )
        try:
            await message.delete()
        except Exception:
            pass
        return

    if is_whitelisted(message.author, cfg):
        return

    # ── AutoMod ──
    am = cfg["automod"]
    if am["enabled"] and not is_exempt(message.author, cfg, "automod"):
        author_roles = [r.id for r in getattr(message.author, "roles", [])]
        bypass       = [int(r) for r in am.get("bypass_roles", []) if r]
        if not any(r in bypass for r in author_roles):
            content = message.content
            cl      = content.lower()
            for word in am.get("banned_words", []):
                if word and word.lower() in cl:
                    try: await message.delete()
                    except: pass
                    await apply_punishment(guild, message.author, am.get("punishment","timeout"),
                                          "AutoMod: คำต้องห้าม", am.get("mute_duration",5))
                    return
            if am.get("filter_links") and RE_LINK.search(content):
                try: await message.delete()
                except: pass
                await apply_punishment(guild, message.author, am.get("punishment","timeout"),
                                       "AutoMod: ลิงก์", am.get("mute_duration",5))
                return
            if am.get("filter_invites") and RE_INVITE.search(content):
                try: await message.delete()
                except: pass
                await apply_punishment(guild, message.author, am.get("punishment","timeout"),
                                       "AutoMod: invite link", am.get("mute_duration",5))
                return
            if am.get("filter_caps"):
                letters = [c for c in content if c.isalpha()]
                if len(letters) > 8 and sum(1 for c in letters if c.isupper()) / len(letters) > 0.7:
                    try: await message.delete()
                    except: pass
                    await apply_punishment(guild, message.author, am.get("punishment","timeout"),
                                           "AutoMod: caps spam", am.get("mute_duration",5))
                    return

    # ── Anti-Text Spam ──
    if not is_exempt(message.author, cfg, "spam"):
        await _check_text_spam(message, cfg)

    # ── Anti-Mass Mentions ──
    if not is_exempt(message.author, cfg, "mentions"):
        await _check_mass_mentions(message, cfg)

    # ── Anti-Link Spam ──
    if not is_exempt(message.author, cfg, "links"):
        await _check_link_spam(message, cfg)

    # ── Anti-Attachment Spam ──
    if not is_exempt(message.author, cfg, "spam"):
        await _check_att_spam(message, cfg)

    # ── Anti-Emoji Spam ──
    if not is_exempt(message.author, cfg, "spam"):
        await _check_emoji_spam(message, cfg)

# ══════════════════════════════════════════════════════════════════
#  ANTI-SPAM — ฟังก์ชันย่อย
#
#  _rate_check()         — sliding-window ใช้ร่วมกัน: นับ event ใน window วินาที
#                          คืน (exceeded, track) → ถ้า exceeded ให้ caller ลงโทษเอง
#
#  _check_text_spam()    — ส่งข้อความถี่เกิน N ครั้งใน window วินาที
#  _check_mass_mentions() — แท็ก @user / @role / @everyone เกิน N ครั้งในข้อความเดียว
#  _check_link_spam()    — ส่งลิงก์/invite เกิน N ครั้งใน window วินาที
#  _check_att_spam()     — ส่งไฟล์แนบเกิน N ครั้งใน window วินาที
#  _check_emoji_spam()   — ใช้ emoji (custom + unicode) เกิน N ตัวในข้อความเดียว
#
#  ทุกตัวทำงานเหมือนกัน: ตรวจ enabled → rate check → ลบข้อความ → ลงโทษ → ส่ง log
# ══════════════════════════════════════════════════════════════════
# ── Spam sub-functions ──────────────────────────────────────────
def _rate_check(tracker, guild_id, user_id, feat, now):
    """Return (exceeded, track) — synchronous, no I/O."""
    window = feat.get("window", 5)
    limit  = feat.get("limit", 5)
    track  = tracker[guild_id][user_id]
    track  = [t for t in track if now - t < window]
    track.append(now)
    tracker[guild_id][user_id] = track
    return len(track) >= limit, track

async def _check_text_spam(message: discord.Message, cfg: dict):
    feat = cfg.get("anti_text_spam", {})
    if not feat.get("enabled"):
        return
    now  = datetime.now(timezone.utc).timestamp()
    over, _ = _rate_check(bot.heat, message.guild.id, message.author.id, feat, now)
    # ── per-channel tracking: ถ้า spam เฉพาะห้องเดียวก็จับได้ ──
    ch_over, _ = _rate_check(bot.ch_heat[message.guild.id][message.channel.id],
                              message.guild.id, message.author.id, feat, now)
    over = over or ch_over
    if over:
        bot.heat[message.guild.id][message.author.id] = []
        # ── [Fix] ลบข้อความก่อนลงโทษ (เหมือน link spam / att spam) ──
        try: await message.delete()
        except: pass
        record_action(message.guild.id, message.author.id, "msg_spam",
                      f"text spam >{feat.get('limit',5)}x/{feat.get('window',5)}วิ")
        # ── per-channel heat ──
        bot.ch_heat[message.guild.id][message.channel.id][message.author.id] = []
        await apply_punishment(message.guild, message.author,
                               feat.get("punishment","timeout"), "Anti-Text Spam")
        _ms = int(time.time() * 1000)
        E_ARROW = "⟫"
        E_SEP   = "─────────"
        E_WARN  = "⚠️"
        E_SORT  = "▷"
        _em_sp = discord.Embed(title=f"{E_WARN} Anti-Text Spam", color=0xffa502)
        _em_sp.description = (
            f"{E_ARROW} **ผู้กระทำ:** {message.author.mention} `{message.author}` (ID: `{message.author.id}`)\n"
            f"{E_ARROW} **ห้อง:** {message.channel.mention}\n"
            f"{E_ARROW} **เกิน:** `{feat.get('limit',5)}x` ใน `{feat.get('window',5)}` วินาที\n"
            f"{E_SEP}"
        )
        _em_sp.add_field(name=f"{E_SORT} เวลา (ms)", value=f"`{_ms}`", inline=True)
        _em_sp.add_field(name="📅 Discord timestamp", value=f"<t:{_ms//1000}:F>", inline=True)
        _em_sp.set_footer(text=f"AntiSpam | Guild: {message.guild.id}")
        _em_sp.timestamp = datetime.now(timezone.utc)
        await send_log(message.guild, _em_sp)
        # ── BIE analyze async ──
        asyncio.create_task(bie_analyze(message.guild, message.author.id, "msg_spam"))
        # ── Auto Slowmode: เปิด slowmode 10 วิ ในห้องนั้น 60 วิ ──
        asyncio.create_task(_auto_slowmode(message.channel, 10, 60))
async def _check_mass_mentions(message: discord.Message, cfg: dict):
    feat = cfg.get("anti_mass_mentions", {})
    if not feat.get("enabled"):
        return
    limit = feat.get("limit", 5)
    total_mentions = len(message.mentions) + len(message.role_mentions)
    if message.mention_everyone:
        total_mentions += 2
    # Always record mention activity for suspicious tracking (even below limit)
    if total_mentions > 0:
        record_action(message.guild.id, message.author.id, "mention",
                      f"แท็ก {total_mentions} ครั้ง{'(@everyone)' if message.mention_everyone else ''}")
    if total_mentions < limit:
        return
    try: await message.delete()
    except: pass
    await apply_punishment(message.guild, message.author,
                           feat.get("punishment","timeout"), f"Anti-Mass Mentions: {total_mentions} mentions")
    _ms = int(time.time() * 1000)
    E_ARROW = "⟫"
    E_SEP   = "─────────"
    E_WARN  = "⚠️"
    E_BELL  = "🔔"
    E_SORT  = "▷"
    _em_mm = discord.Embed(title=f"{E_WARN} Anti-Mass Mentions", color=0xffa502)
    _em_mm.description = (
        f"{E_ARROW} **ผู้กระทำ:** {message.author.mention} `{message.author}` (ID: `{message.author.id}`)\n"
        f"{E_BELL} แท็กสมาชิก **{total_mentions} ครั้ง** ในข้อความเดียว\n"
        f"{E_ARROW} **มี @everyone:** `{'ใช่' if message.mention_everyone else 'ไม่'}` | "
        f"**@role:** `{len(message.role_mentions)}` | **@user:** `{len(message.mentions)}`\n"
        f"{E_SEP}"
    )
    _em_mm.add_field(name=f"{E_SORT} เวลา (ms)", value=f"`{_ms}`", inline=True)
    _em_mm.add_field(name="📅 Discord timestamp", value=f"<t:{_ms//1000}:F>", inline=True)
    _em_mm.set_footer(text=f"AntiSpam | Guild: {message.guild.id}")
    _em_mm.timestamp = datetime.now(timezone.utc)
    await send_log(message.guild, _em_mm)
    asyncio.create_task(bie_analyze(message.guild, message.author.id, "mention"))
async def _check_link_spam(message: discord.Message, cfg: dict):
    feat = cfg.get("anti_link_spam", {})
    if not feat.get("enabled"):
        return
    if not (RE_LINK.search(message.content) or RE_INVITE.search(message.content)):
        return
    now  = datetime.now(timezone.utc).timestamp()
    over, _ = _rate_check(bot.link_track, message.guild.id, message.author.id, feat, now)
    if over:
        bot.link_track[message.guild.id][message.author.id] = []
        try: await message.delete()
        except: pass
        await apply_punishment(message.guild, message.author,
                               feat.get("punishment","timeout"), "Anti-Link Spam")
        _ms = int(time.time() * 1000)
        E_ARROW = "⟫"
        E_SEP   = "─────────"
        E_WARN  = "⚠️"
        E_SORT  = "▷"
        _em_lk = discord.Embed(title=f"{E_WARN} Anti-Link Spam", color=0xffa502)
        _em_lk.description = (
            f"{E_ARROW} **ผู้กระทำ:** {message.author.mention} `{message.author}` (ID: `{message.author.id}`)\n"
            f"{E_ARROW} **ห้อง:** {message.channel.mention}\n"
            f"{E_ARROW} **เกิน:** `{feat.get('limit',5)}x` ใน `{feat.get('window',5)}` วินาที\n"
            f"{E_SEP}"
        )
        _em_lk.add_field(name=f"{E_SORT} เวลา (ms)", value=f"`{_ms}`", inline=True)
        _em_lk.add_field(name="📅 Discord timestamp", value=f"<t:{_ms//1000}:F>", inline=True)
        _em_lk.set_footer(text=f"AntiSpam | Guild: {message.guild.id}")
        _em_lk.timestamp = datetime.now(timezone.utc)
        await send_log(message.guild, _em_lk)
        asyncio.create_task(bie_analyze(message.guild, message.author.id, "msg_spam"))
async def _check_att_spam(message: discord.Message, cfg: dict):
    feat = cfg.get("anti_att_spam", {})
    if not feat.get("enabled") or not message.attachments:
        return
    now  = datetime.now(timezone.utc).timestamp()
    over, _ = _rate_check(bot.att_track, message.guild.id, message.author.id, feat, now)
    if over:
        bot.att_track[message.guild.id][message.author.id] = []
        try: await message.delete()
        except: pass
        await apply_punishment(message.guild, message.author,
                               feat.get("punishment","timeout"), "Anti-Attachment Spam")
        _ms = int(time.time() * 1000)
        E_ARROW = "⟫"
        E_SEP   = "─────────"
        E_WARN  = "⚠️"
        E_SORT  = "▷"
        _em_at = discord.Embed(title=f"{E_WARN} Anti-Attachment Spam", color=0xffa502)
        _em_at.description = (
            f"{E_ARROW} **ผู้กระทำ:** {message.author.mention} `{message.author}` (ID: `{message.author.id}`)\n"
            f"{E_ARROW} **ห้อง:** {message.channel.mention}\n"
            f"{E_ARROW} **เกิน:** `{feat.get('limit',5)}x` ใน `{feat.get('window',5)}` วินาที\n"
            f"{E_SEP}"
        )
        _em_at.add_field(name=f"{E_SORT} เวลา (ms)", value=f"`{_ms}`", inline=True)
        _em_at.add_field(name="📅 Discord timestamp", value=f"<t:{_ms//1000}:F>", inline=True)
        _em_at.set_footer(text=f"AntiSpam | Guild: {message.guild.id}")
        _em_at.timestamp = datetime.now(timezone.utc)
        await send_log(message.guild, _em_at)
async def _check_emoji_spam(message: discord.Message, cfg: dict):
    feat = cfg.get("anti_emoji_spam", {})
    if not feat.get("enabled"):
        return
    limit = feat.get("limit", 10)
    # นับ custom emoji (<:name:id> และ animated <a:name:id>) + unicode emoji (codepoint ≥ 0x1F300)
    custom_emoji = message.content.count("<:") + message.content.count("<a:")
    unicode_emoji = sum(1 for c in message.content if ord(c) >= 0x1F300)
    emoji_count = custom_emoji + unicode_emoji
    if emoji_count < limit:
        return
    try: await message.delete()
    except: pass
    await apply_punishment(message.guild, message.author,
                           feat.get("punishment","timeout"), f"Anti-Emoji Spam: {emoji_count} emoji")
    _ms = int(time.time() * 1000)
    E_ARROW = "⟫"
    E_SEP   = "─────────"
    E_WARN  = "⚠️"
    E_SORT  = "▷"
    E_BELL  = "🔔"
    _em_ej = discord.Embed(title=f"{E_WARN} Anti-Emoji Spam", color=0xffa502)
    _em_ej.description = (
        f"{E_ARROW} **ผู้กระทำ:** {message.author.mention} `{message.author}` (ID: `{message.author.id}`)\n"
        f"{E_BELL} ส่ง emoji **{emoji_count} ตัว** ในข้อความเดียว\n"
        f"{E_ARROW} **ห้อง:** {message.channel.mention}\n"
        f"{E_SEP}"
    )
    _em_ej.add_field(name=f"{E_SORT} เวลา (ms)", value=f"`{_ms}`", inline=True)
    _em_ej.add_field(name="📅 Discord timestamp", value=f"<t:{_ms//1000}:F>", inline=True)
    _em_ej.set_footer(text=f"AntiSpam | Guild: {message.guild.id}")
    _em_ej.timestamp = datetime.now(timezone.utc)
    await send_log(message.guild, _em_ej)
async def _auto_slowmode(channel: discord.TextChannel, delay_sec: int, duration_sec: int):
    """เปิด slowmode ชั่วคราวในห้องที่โดน spam แล้วคืนค่าเดิมหลังจาก duration_sec วิ"""
    try:
        old_delay = channel.slowmode_delay
        if old_delay >= delay_sec:
            return  # มี slowmode อยู่แล้ว ไม่ต้องเพิ่ม
        await channel.edit(slowmode_delay=delay_sec, reason="Anti-Spam: Auto Slowmode")
        await asyncio.sleep(duration_sec)
        await channel.edit(slowmode_delay=old_delay, reason="Anti-Spam: คืน Slowmode")
    except Exception:
        pass

# ══════════════════════════════════════════════════════════════════
#  REACTION SPAM
#  ใช้ react_track + _rate_check() เหมือนกับ spam ข้อความ
#  ใช้ค่า limit/window จาก anti_emoji_spam config (feature เดียวกัน)
# ══════════════════════════════════════════════════════════════════
@bot.event
async def on_reaction_add(reaction: discord.Reaction, user: discord.User):
    if user.bot or not reaction.message.guild:
        return
    guild  = reaction.message.guild
    cfg    = get_cfg(guild.id)
    feat   = cfg.get("anti_emoji_spam", {})
    if not feat.get("enabled"):
        return
    now  = datetime.now(timezone.utc).timestamp()
    over, _ = _rate_check(bot.react_track, guild.id, user.id, feat, now)
    if over:
        bot.react_track[guild.id][user.id] = []
        member = guild.get_member(user.id)
        if member and not is_whitelisted(member, cfg):
            await apply_punishment(guild, member,
                                   feat.get("punishment","timeout"), "Anti-Reaction Spam")

# ══════════════════════════════════════════════════════════════════
#  JOIN GATE + ANTI-RAID + ANTI-JOIN-FLOOD
# ══════════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════
#  JOIN GATE + ANTI-RAID + ANTI-JOIN-FLOOD
#  on_member_join() เป็นจุดตรวจสมาชิกใหม่ทุกคนที่เข้า server
#
#  ลำดับการตรวจ:
#  1. Welcome message (ถ้าเปิด)
#  2. Anti-Account Age — เตะบัญชีที่อายุน้อยกว่า N วัน
#  3. Anti-No Avatar   — เตะบัญชีที่ไม่มีรูปโปรไฟล์
#  4. Anti-Bot Add     — ตรวจจากบอทที่ถูกเชิญเข้า: หาผู้เชิญจาก audit log แล้วลงโทษ
#  5. Anti-Join Flood  — นับ join ใน window วินาที ถ้าเกิน limit → เปิด raid_mode
#                        (raid_mode: member ใหม่ทุกคนถูกเตะอัตโนมัติชั่วคราว)
# ══════════════════════════════════════════════════════════════════
@bot.event
async def on_member_join(member: discord.Member):
    guild = member.guild
    cfg   = get_cfg(guild.id)
    age   = (datetime.now(timezone.utc) - member.created_at).days

    # ── Welcome ──
    wlc = cfg.get("welcome", {})
    if wlc.get("enabled") and wlc.get("channel_id"):
        try:
            ch = guild.get_channel(int(wlc["channel_id"]))
            if ch:
                msg = (wlc.get("message","ยินดีต้อนรับ {user}!")
                       .replace("{user}", member.mention)
                       .replace("{server}", guild.name)
                       .replace("{count}", str(guild.member_count)))
                em = discord.Embed(description=msg, color=0x5865F2)
                em.set_thumbnail(url=member.display_avatar.url)
                await ch.send(embed=em)
        except Exception as e:
            log.error(f"[Welcome] guild {guild.id}: {e}")

    # ── Anti-Account Age ──
    age_feat = cfg.get("anti_account_age", {})
    if age_feat.get("enabled") and not is_exempt(member, cfg, "raid"):
        min_days = age_feat.get("limit", 7)
        if age < min_days:
            try: await member.send(f"❌ บัญชีของคุณอายุน้อยเกินไป ({age} วัน / ต้องการอย่างน้อย {min_days} วัน)")
            except: pass
            await apply_punishment(guild, member, age_feat.get("punishment","kick"),
                                   f"Anti-Account Age: บัญชีอายุ {age} วัน")
            return

    # ── Anti-No Avatar ──
    av_feat = cfg.get("anti_no_avatar", {})
    if av_feat.get("enabled") and member.avatar is None and not is_exempt(member, cfg, "raid"):
        try: await member.send("❌ กรุณาตั้งรูปโปรไฟล์ก่อนเข้าร่วม Server")
        except: pass
        await apply_punishment(guild, member, av_feat.get("punishment","kick"),
                               "Anti-Default Avatar: ไม่มีรูปโปรไฟล์")
        return

    # ── Anti-Bot Add (bot joining via invite) ──
    if member.bot:
        feat = cfg.get("anti_bot_add", {})
        if feat.get("enabled"):
            wl_bots = [int(x) for x in feat.get("bot_whitelist", []) if x]
            if member.id not in wl_bots:
                # [Speed] ไม่ดึง audit log ซ้ำ — on_audit_log_entry_create จัดการ punish inviter แล้ว
                # on_member_join แค่เตะบอทตัวนั้นออกทันที
                try: await member.kick(reason="Anti-Bot Add: บอทไม่อยู่ใน whitelist")
                except: pass
        return

    # ── Anti-Join Flood ──
    flood_feat = cfg.get("anti_join_flood", {})
    if flood_feat.get("enabled"):
        now    = datetime.now(timezone.utc).timestamp()
        window = flood_feat.get("window", 60)
        limit  = flood_feat.get("limit", 10)
        bot.join_tracker[guild.id] = [t for t in bot.join_tracker[guild.id] if now - t < window]
        bot.join_tracker[guild.id].append(now)
        if len(bot.join_tracker[guild.id]) >= limit and guild.id not in bot.raid_mode:
            bot.raid_mode.add(guild.id)
            _ms = int(time.time() * 1000)
            E_ARROW  = "⟫"
            E_SEP    = "─────────"
            E_DANGER = "🔴"
            E_ALERT  = "🚨"
            E_BELL   = "🔔"
            E_SORT   = "▷"
            em = discord.Embed(title=f"{E_DANGER} RAID DETECTED — Raid Mode เปิดแล้ว", color=0xf85149)
            em.description = (
                f"{E_ARROW} มีบัญชีเข้าร่วม **{limit}+ คน** ใน `{window}` วินาที\n"
                f"{E_BELL} สมาชิกใหม่ทุกคนจะถูกเตะอัตโนมัติ\n"
                f"{E_SEP}\n"
                f"{E_ALERT} **Raid Mode จะปิดอัตโนมัติใน 10 นาที**"
            )
            em.add_field(name=f"{E_SORT} เวลา (ms)", value=f"`{_ms}`", inline=True)
            em.add_field(name="📅 Discord timestamp", value=f"<t:{_ms//1000}:F>", inline=True)
            em.set_footer(text=f"AntiRaid | Guild: {guild.id}")
            em.timestamp = datetime.now(timezone.utc)
            await send_log(guild, em)
            asyncio.create_task(_disable_raid(guild.id))
        if guild.id in bot.raid_mode:
            await apply_punishment(guild, member, flood_feat.get("punishment","kick"),
                                   "Anti-Join Flood: Raid Mode active")
            return

    # ── Log ──
    _ms = int(time.time() * 1000)
    E_ARROW = "⟫"
    E_SEP   = "─────────"
    E_OK    = "✅"
    E_ROLE  = "🏷️"
    E_SORT  = "▷"
    E_BELL  = "🔔"
    em = discord.Embed(title=f"{E_OK} สมาชิกเข้าร่วม", color=0x3fb950)
    em.set_thumbnail(url=member.display_avatar.url)
    em.description = (
        f"{E_ARROW} **สมาชิก:** {member.mention} `{member}` (ID: `{member.id}`)\n"
        f"{E_ARROW} **อายุบัญชี:** `{age} วัน` (<t:{int(member.created_at.timestamp())}:R>)\n"
        f"{E_BELL} **สมาชิกลำดับที่:** `{guild.member_count}`\n"
        f"{E_SEP}"
    )
    em.add_field(name=f"{E_SORT} เวลา (ms)", value=f"`{_ms}`", inline=True)
    em.add_field(name="📅 Discord timestamp", value=f"<t:{_ms//1000}:F>", inline=True)
    em.set_footer(text=f"User ID: {member.id} | Guild: {guild.id}")
    em.timestamp = datetime.now(timezone.utc)
    await send_log(guild, em, "member_join")
async def _disable_raid(guild_id: int):
    await asyncio.sleep(600)
    bot.raid_mode.discard(guild_id)
    guild = bot.get_guild(guild_id)
    if guild:
        _ms = int(time.time() * 1000)
        E_OK   = "✅"
        E_SORT = "▷"
        E_SEP  = "─────────"
        _em_rd = discord.Embed(title=f"{E_OK} Raid Mode ปิดแล้ว", color=0x3fb950)
        _em_rd.description = f"⟫ ระบบป้องกัน Raid ถูกปิดอัตโนมัติหลัง 10 นาที\n{E_SEP}"
        _em_rd.add_field(name=f"{E_SORT} เวลา (ms)", value=f"`{_ms}`", inline=True)
        _em_rd.add_field(name="📅 Discord timestamp", value=f"<t:{_ms//1000}:F>", inline=True)
        _em_rd.timestamp = datetime.now(timezone.utc)
        await send_log(guild, _em_rd)

# ══════════════════════════════════════════════════════════════════
#  SERVER LOCKDOWN — do_lockdown()
#  ล็อก/ปลดล็อก server ฉุกเฉินระดับช่อง (channel-level)
#
#  enable=True  (ล็อก):
#    1. บันทึก send_messages + add_reactions เดิมของทุก text channel ลง cfg["_lockdown_state"]
#    2. ตั้ง send_messages=False, add_reactions=False สำหรับ @everyone ทุกช่อง
#    3. ยกเลิก invite ทั้งหมดใน server
#
#  enable=False (ปลดล็อก):
#    1. ดึงค่าเดิมจาก cfg["_lockdown_state"]
#    2. คืน permissions ทุกช่องกลับตามที่บันทึกไว้
#
#  ป้องกัน double-lock: ถ้า _lockdown_state มีอยู่แล้วจะ return ทันที
#  เรียกใช้ได้จาก: /lockdown slash command, POST /api/lockdown, หรือ api_post_config
# ══════════════════════════════════════════════════════════════════
async def do_lockdown(guild: discord.Guild, enable: bool):
    cfg = get_cfg(guild.id)
    if enable:
        if cfg.get("_lockdown_state"):
            return
        saved = {}
        for ch in guild.text_channels:
            try:
                old = ch.overwrites_for(guild.default_role)
                saved[str(ch.id)] = {"send_messages": old.send_messages, "add_reactions": old.add_reactions}
                await ch.set_permissions(guild.default_role,
                                         send_messages=False, add_reactions=False,
                                         reason="Server Lockdown")
            except Exception:
                pass
        cfg["_lockdown_state"] = saved
        await save_guild_data(guild.id)
        # Disable all active invites
        try:
            for inv in await guild.invites():
                await inv.delete(reason="Server Lockdown")
        except Exception:
            pass
        _ms = int(time.time() * 1000)
        E_DANGER = "🔴"
        E_CANCEL = "❌"
        E_ARROW  = "⟫"
        E_SEP    = "─────────"
        E_SORT   = "▷"
        em = discord.Embed(title=f"{E_DANGER} Server Lockdown เปิดแล้ว", color=0xf85149)
        em.description = (
            f"{E_ARROW} ปิดการพิมพ์ทุกห้องชั่วคราว\n"
            f"{E_CANCEL} ยกเลิกลิงก์เชิญทั้งหมดแล้ว\n"
            f"{E_SEP}\n"
            f"**ปลดล็อกได้จาก Dashboard หรือคำสั่ง `/lockdown`**"
        )
        em.add_field(name=f"{E_SORT} เวลา (ms)", value=f"`{_ms}`", inline=True)
        em.add_field(name="📅 Discord timestamp", value=f"<t:{_ms//1000}:F>", inline=True)
        em.set_footer(text=f"ServerLockdown | Guild: {guild.id}")
        em.timestamp = datetime.now(timezone.utc)
        await send_log(guild, em)
    else:
        if not cfg.get("_lockdown_state"):
            return  # ไม่ได้ล็อกอยู่ ไม่ต้องทำอะไร
        saved = cfg.pop("_lockdown_state", {})
        cfg["_lockdown_state"] = {}
        for ch in guild.text_channels:
            try:
                data = saved.get(str(ch.id), {})
                await ch.set_permissions(guild.default_role,
                                         send_messages=data.get("send_messages"),
                                         add_reactions=data.get("add_reactions"),
                                         reason="Server Lockdown: ยกเลิก")
            except Exception:
                pass
        await save_guild_data(guild.id)
        _ms = int(time.time() * 1000)
        em = discord.Embed(
            title="🔓 Server Lockdown ปิดแล้ว",
            description=(
                f"```ansi\n\u001b[32m◉  LOCKDOWN LIFTED\u001b[0m\n```\n"
                f"🔓 คืนสิทธิ์ทุกห้องเรียบร้อยแล้ว"
            ),
            color=0x3fb950,
        )
        em.set_author(name=f"{guild.name}  ›  Lockdown Log", icon_url=guild.icon.url if guild.icon else None)
        em.add_field(name="🕐 เวลา", value=f"<t:{_ms//1000}:F>", inline=True)
        em.add_field(name="📅 Relative", value=f"<t:{_ms//1000}:R>", inline=True)
        em.set_footer(text=f"ServerLockdown  •  Guild: {guild.id}")
        em.timestamp = datetime.now(timezone.utc)
        await send_log(guild, em)

# ══════════════════════════════════════════════════════════════════
#  ANTI-NUKE EVENTS
# ══════════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════
#  ANTI-NUKE EVENTS
#  event handler แต่ละตัวทำงานเหมือนกัน:
#    1. สร้าง embed สำหรับ log
#    2. ดึง Discord Audit Log ใน background task (_audit) เพื่อหาว่าใครเป็นคนทำ
#    3. เรียก check_feature() → ถ้าเกิน rate limit จะลงโทษทันที
#    4. เรียก record_action() → บันทึกให้ Suspicious Behavior Tracker วิเคราะห์
#    5. ส่ง embed ไปห้อง log
#
#  Event ที่มี handler:
#    on_member_ban        → anti_ban
#    on_member_remove     → anti_kick (ตรวจว่าเป็นการเตะจาก audit log)
#    on_member_unban      → log เท่านั้น
#    on_guild_channel_create → anti_ch_create
#    on_guild_channel_delete → anti_ch_delete
#    on_guild_channel_update → anti_ch_update (ข้ามถ้ากำลัง lockdown อยู่)
#    on_guild_role_create    → anti_role_create
#    on_guild_role_delete    → anti_role_delete
#    on_guild_role_update    → anti_role_update (ข้ามถ้า adv_lock กำลังทำงาน)
#    on_member_update        → anti_role_give (เฉพาะยศที่มีสิทธิ์อันตราย)
#    on_guild_update         → anti_guild_update + anti_vanity (ตรวจ vanity URL เปลี่ยน)
#    on_audit_log_entry_create → anti_prune, anti_integration, anti_webhook_create/delete
# ══════════════════════════════════════════════════════════════════
@bot.event
async def on_member_ban(guild: discord.Guild, user: discord.User):
    # [Session 7] check_feature และ record_action ถูกย้ายไปจัดการใน on_audit_log_entry_create แล้ว
    _ms = int(time.time() * 1000)
    em = discord.Embed(
        title="⛔ แบนสมาชิก",
        description=(
            f"```ansi\n\u001b[31m◉  MEMBER BANNED\u001b[0m\n```\n"
            f"👤 **ผู้ถูกแบน**\n> {user.mention} — `{user}` (`{user.id}`)"
        ),
        color=0xef4444,
    )
    em.set_author(name=f"{guild.name}  ›  Ban Log", icon_url=guild.icon.url if guild.icon else None)
    if user.display_avatar:
        em.set_thumbnail(url=user.display_avatar.url)
    em.add_field(name="🕐 เวลา", value=f"<t:{_ms//1000}:F>", inline=True)
    em.add_field(name="📅 Relative", value=f"<t:{_ms//1000}:R>", inline=True)
    em.set_footer(text=f"User ID: {user.id}  •  Guild: {guild.id}")
    em.timestamp = datetime.now(timezone.utc)
    await send_log(guild, em, "member_ban")
@bot.event
async def on_member_remove(member: discord.Member):
    # [Session 7] check_feature และ record_action ถูกย้ายไปจัดการใน on_audit_log_entry_create แล้ว
    guild = member.guild
    _ms = int(time.time() * 1000)
    age_days = (datetime.now(timezone.utc) - member.created_at).days
    roles_str = " ".join(r.mention for r in member.roles if r.name != "@everyone") or "`ไม่มียศ`"
    em = discord.Embed(
        title="📤 สมาชิกออกจาก Server",
        description=(
            f"```ansi\n\u001b[33m◉  MEMBER LEFT\u001b[0m\n```\n"
            f"👤 **สมาชิก**\n> {member.mention} — `{member}` (`{member.id}`)\n\n"
            f"📅 **อายุบัญชี**\n> `{age_days} วัน`"
        ),
        color=0xf85149,
    )
    em.set_author(name=f"{guild.name}  ›  Leave Log", icon_url=guild.icon.url if guild.icon else None)
    em.set_thumbnail(url=member.display_avatar.url)
    em.add_field(name="🏷️ ยศที่มี", value=roles_str[:500], inline=False)
    em.add_field(name="🕐 เวลา", value=f"<t:{_ms//1000}:F>", inline=True)
    em.add_field(name="📅 Relative", value=f"<t:{_ms//1000}:R>", inline=True)
    em.set_footer(text=f"User ID: {member.id}  •  Guild: {guild.id}")
    em.timestamp = datetime.now(timezone.utc)
    await send_log(guild, em, "member_leave")
@bot.event
async def on_member_unban(guild: discord.Guild, user: discord.User):
    _ms = int(time.time() * 1000)
    em = discord.Embed(
        title="✅ ยกเลิกแบน",
        description=(
            f"```ansi\n\u001b[32m◉  BAN REMOVED\u001b[0m\n```\n"
            f"👤 **ผู้ถูกยกเลิกแบน**\n> {user.mention} — `{user}` (`{user.id}`)"
        ),
        color=0x3fb950,
    )
    em.set_author(name=f"{guild.name}  ›  Unban Log", icon_url=guild.icon.url if guild.icon else None)
    if user.display_avatar:
        em.set_thumbnail(url=user.display_avatar.url)
    em.add_field(name="🕐 เวลา", value=f"<t:{_ms//1000}:F>", inline=True)
    em.add_field(name="📅 Relative", value=f"<t:{_ms//1000}:R>", inline=True)
    em.set_footer(text=f"User ID: {user.id}  •  Guild: {guild.id}")
    em.timestamp = datetime.now(timezone.utc)
    await send_log(guild, em)
@bot.event
async def on_guild_channel_create(channel: discord.abc.GuildChannel):
    # [Session 7] check_feature ถูกย้ายไปจัดการใน on_audit_log_entry_create แล้ว
    if channel.name.startswith(DATA_CH_PREFIX):
        return
    _ms = int(time.time() * 1000)
    ch_type = type(channel).__name__.replace("Channel","").lower()
    em = discord.Embed(
        title="✅ สร้างช่องใหม่",
        description=(
            f"```ansi\n\u001b[32m◉  CHANNEL CREATED\u001b[0m\n```\n"
            f"📢 **ช่อง**\n> `{channel.name}` (`{channel.id}`)\n\n"
            f"🗂️ **ประเภท / Category**\n> `{ch_type}` › `{channel.category.name if channel.category else '-'}`"
        ),
        color=0x3fb950,
    )
    em.set_author(name=f"{channel.guild.name}  ›  Channel Log", icon_url=channel.guild.icon.url if channel.guild.icon else None)
    em.add_field(name="🕐 เวลา", value=f"<t:{_ms//1000}:F>", inline=True)
    em.add_field(name="📅 Relative", value=f"<t:{_ms//1000}:R>", inline=True)
    em.set_footer(text=f"Channel ID: {channel.id}  •  Guild: {channel.guild.id}")
    em.timestamp = datetime.now(timezone.utc)
    await send_log(channel.guild, em, "channel_update")
@bot.event
async def on_guild_channel_delete(channel: discord.abc.GuildChannel):
    # [Session 7] check_feature และ record_action ถูกย้ายไปจัดการใน on_audit_log_entry_create แล้ว
    _ms = int(time.time() * 1000)
    ch_type = type(channel).__name__.replace("Channel","").lower()
    em = discord.Embed(
        title="🗑️ ลบช่อง",
        description=(
            f"```ansi\n\u001b[31m◉  CHANNEL DELETED\u001b[0m\n```\n"
            f"📢 **ช่อง**\n> `{channel.name}` (`{channel.id}`)\n\n"
            f"🗂️ **ประเภท / Category**\n> `{ch_type}` › `{channel.category.name if channel.category else '-'}`"
        ),
        color=0xef4444,
    )
    em.set_author(name=f"{channel.guild.name}  ›  Channel Log", icon_url=channel.guild.icon.url if channel.guild.icon else None)
    em.add_field(name="🕐 เวลา", value=f"<t:{_ms//1000}:F>", inline=True)
    em.add_field(name="📅 Relative", value=f"<t:{_ms//1000}:R>", inline=True)
    em.set_footer(text=f"Channel ID: {channel.id}  •  Guild: {channel.guild.id}")
    em.timestamp = datetime.now(timezone.utc)
    await send_log(channel.guild, em, "channel_update")
@bot.event
async def on_guild_channel_update(before: discord.abc.GuildChannel, after: discord.abc.GuildChannel):
    # [Session 7] check_feature ถูกย้ายไปจัดการใน on_audit_log_entry_create แล้ว (รวมการตรวจ lockdown state)
    pass

@bot.event
async def on_guild_role_create(role: discord.Role):
    # [Session 7] check_feature ถูกย้ายไปจัดการใน on_audit_log_entry_create แล้ว
    _ms = int(time.time() * 1000)
    danger_perms = [p for p in ["administrator","manage_guild","ban_members","kick_members",
                                 "manage_roles","manage_channels","manage_webhooks"]
                    if getattr(role.permissions, p, False)]
    danger_val = " ".join(f"`{p}`" for p in danger_perms) if danger_perms else "`ไม่มี`"
    danger_warn = f"\n\n⚠️ **สิทธิ์อันตราย!** มี `{len(danger_perms)}` สิทธิ์" if danger_perms else ""
    em = discord.Embed(
        title="🏷️ สร้างยศใหม่",
        description=(
            f"```ansi\n\u001b[32m◉  ROLE CREATED\u001b[0m\n```\n"
            f"🏷️ **ยศ**\n> `{role.name}` (`{role.id}`)\n\n"
            f"🎨 **สี / Position**\n> `{str(role.color)}` › ตำแหน่ง `{role.position}`"
            f"{danger_warn}"
        ),
        color=role.color.value if role.color.value else 0x3fb950,
    )
    em.set_author(name=f"{role.guild.name}  ›  Role Log", icon_url=role.guild.icon.url if role.guild.icon else None)
    em.add_field(name="🔐 สิทธิ์อันตราย", value=danger_val, inline=False)
    em.add_field(name="🕐 เวลา", value=f"<t:{_ms//1000}:F>", inline=True)
    em.add_field(name="📅 Relative", value=f"<t:{_ms//1000}:R>", inline=True)
    em.set_footer(text=f"Role ID: {role.id}  •  Guild: {role.guild.id}")
    em.timestamp = datetime.now(timezone.utc)
    await send_log(role.guild, em, "role_update")
@bot.event
async def on_guild_role_delete(role: discord.Role):
    # [Session 7] check_feature และ record_action ถูกย้ายไปจัดการใน on_audit_log_entry_create แล้ว
    _ms = int(time.time() * 1000)
    danger_perms = [p for p in ["administrator","manage_guild","ban_members","kick_members",
                                 "manage_roles","manage_channels","manage_webhooks"]
                    if getattr(role.permissions, p, False)]
    danger_val = " ".join(f"`{p}`" for p in danger_perms) if danger_perms else "`ไม่มีสิทธิ์อันตราย`"
    em = discord.Embed(
        title="🗑️ ลบยศ",
        description=(
            f"```ansi\n\u001b[31m◉  ROLE DELETED\u001b[0m\n```\n"
            f"🏷️ **ยศ**\n> `{role.name}` (`{role.id}`)\n\n"
            f"🎨 **สี / Position**\n> `{str(role.color)}` › ตำแหน่ง `{role.position}`"
        ),
        color=0xef4444,
    )
    em.set_author(name=f"{role.guild.name}  ›  Role Log", icon_url=role.guild.icon.url if role.guild.icon else None)
    em.add_field(name="🔐 สิทธิ์ที่ยศนี้เคยมี", value=danger_val, inline=False)
    em.add_field(name="🕐 เวลา", value=f"<t:{_ms//1000}:F>", inline=True)
    em.add_field(name="📅 Relative", value=f"<t:{_ms//1000}:R>", inline=True)
    em.set_footer(text=f"Role ID: {role.id}  •  Guild: {role.guild.id}")
    em.timestamp = datetime.now(timezone.utc)
    await send_log(role.guild, em, "role_update")
@bot.event
async def on_guild_role_update(before: discord.Role, after: discord.Role):
    # [Session 7] check_feature ถูกย้ายไปจัดการใน on_audit_log_entry_create แล้ว (รวมการตรวจ adv_lock_active)
    pass

@bot.event
async def on_member_update(before: discord.Member, after: discord.Member):
    guild = before.guild
    cfg   = get_cfg(guild.id)
    added   = [r for r in after.roles if r not in before.roles]
    removed = [r for r in before.roles if r not in after.roles]

    # ── ถ้าบอทกำลัง quarantine สมาชิกคนนี้อยู่ → ข้ามทั้งหมด ป้องกัน loop ──
    if (guild.id, after.id) in bot._quarantine_in_progress:
        return

    if added:
        # [Session 7] check_feature และ record_action สำหรับ anti_role_give
        # ถูกย้ายไปจัดการใน on_audit_log_entry_create แล้ว (รวม dangerous perm check)
        pass

    if added or removed:
        _ms = int(time.time() * 1000)
        danger = [r for r in added if any(getattr(r.permissions, p, False)
                  for p in ["administrator","manage_guild","ban_members","kick_members",
                            "manage_roles","manage_channels","manage_webhooks"])] if added else []
        has_danger = len(danger) > 0
        em = discord.Embed(
            title="🏷️ ยศสมาชิกเปลี่ยนแปลง",
            description=(
                f"```ansi\n\u001b[{'31m⚠  DANGEROUS ROLE ASSIGNED' if has_danger else '34m◉  ROLE UPDATED'}\u001b[0m\n```\n"
                f"👤 **สมาชิก**\n> {after.mention} — `{after}` (`{after.id}`)"
            ),
            color=0xff4757 if has_danger else 0x5865F2,
        )
        em.set_author(name=f"{guild.name}  ›  Role Update Log", icon_url=guild.icon.url if guild.icon else None)
        em.set_thumbnail(url=after.display_avatar.url)
        if added:
            danger_tag = f"  ⚠️ **{len(danger)} สิทธิ์อันตราย!**" if has_danger else ""
            em.add_field(
                name=f"✅ ได้รับยศ{danger_tag}",
                value=" ".join(r.mention for r in added)[:500],
                inline=False,
            )
        if removed:
            em.add_field(
                name="❌ ถูกถอดยศ",
                value=" ".join(r.mention for r in removed)[:500],
                inline=False,
            )
        em.add_field(name="🕐 เวลา", value=f"<t:{_ms//1000}:F>", inline=True)
        em.add_field(name="📅 Relative", value=f"<t:{_ms//1000}:R>", inline=True)
        em.set_footer(text=f"User ID: {after.id}  •  Guild: {guild.id}")
        em.timestamp = datetime.now(timezone.utc)
        async def _audit_log_who():
            try:
                async for entry in guild.audit_logs(limit=1, action=discord.AuditLogAction.member_role_update):
                    em.add_field(name="👮 ดำเนินการโดย", value=str(entry.user), inline=True)
            except Exception:
                pass
        asyncio.create_task(_audit_log_who())
        await send_log(guild, em, "role_update")

    if before.nick != after.nick:
        _ms = int(time.time() * 1000)
        em = discord.Embed(
            title="✏️ เปลี่ยนชื่อเล่น",
            description=(
                f"```ansi\n\u001b[36m◉  NICKNAME CHANGED\u001b[0m\n```\n"
                f"👤 **สมาชิก**\n> {after.mention} — `{after}` (`{after.id}`)"
            ),
            color=0x8b5cf6,
        )
        em.set_author(name=f"{guild.name}  ›  Nickname Log", icon_url=guild.icon.url if guild.icon else None)
        em.set_thumbnail(url=after.display_avatar.url)
        em.add_field(name="📝 ก่อน", value=f"`{before.nick or '(ไม่มี)'}`", inline=True)
        em.add_field(name="📝 หลัง", value=f"`{after.nick or '(ไม่มี)'}`", inline=True)
        em.add_field(name="🕐 เวลา", value=f"<t:{_ms//1000}:F>", inline=True)
        em.add_field(name="📅 Relative", value=f"<t:{_ms//1000}:R>", inline=True)
        em.set_footer(text=f"User ID: {after.id}  •  Guild: {guild.id}")
        em.timestamp = datetime.now(timezone.utc)
        await send_log(guild, em)

# webhook_create / webhook_delete ถูกจับใน on_audit_log_entry_create แล้ว
# on_webhooks_update ถูกลบออกเพื่อป้องกัน double-trigger
@bot.event
async def on_guild_update(before: discord.Guild, after: discord.Guild):
    # [Session 7] check_feature ถูกย้ายไปจัดการใน on_audit_log_entry_create แล้ว

    # Anti-Vanity URL
    cfg = get_cfg(after.id)
    feat = cfg.get("anti_vanity", {})
    if feat.get("enabled"):
        old_vanity = bot.vanity_cache.get(after.id)
        try:
            new_inv = await after.vanity_invite()
            new_code = new_inv.code if new_inv else None
        except Exception:
            new_code = None
        if old_vanity and old_vanity != new_code:
            # Someone changed/removed the vanity URL — restore it
            try:
                await after.edit(vanity_code=old_vanity, reason="Anti-Vanity: ดึง URL กลับ")
            except Exception as e:
                log.error(f"Anti-Vanity restore error: {e}")
            # [Audit Session 5] ลบ audit_logs HTTP query ออก — check_feature ถูกจัดการใน on_audit_log_entry_create แล้ว (ป้องกัน double-trigger)
        else:
            bot.vanity_cache[after.id] = new_code

# integration_create / integration_update ถูกจับใน on_audit_log_entry_create แล้ว

# ══════════════════════════════════════════════════════════════════
#  EVENT-DRIVEN LAYER (ชั้นที่ 1) — on_audit_log_entry_create
#
#  [Session 7] รับ actor จาก Gateway โดยตรง ไม่ต้องยิง HTTP audit_logs query
#  ทำงานก่อน event handler ปกติ ส่ง actor ตรงๆ ให้ทั้ง:
#    - check_feature() (ระบบ A: ลงโทษทันที)
#    - do_advanced_lockdown() (ระบบ B: ล็อค permissions ก่อน ถ้าเปิดไว้)
#
#  ACTION_FEATURE_MAP: map discord action → (feature_key, label)
#  ครอบคลุมทุก action ที่ Anti-Nuke ตรวจสอบ
# ══════════════════════════════════════════════════════════════════
_ACTION_FEATURE_MAP = {
    discord.AuditLogAction.ban:                  ("anti_ban",            "Anti-Ban"),
    discord.AuditLogAction.kick:                 ("anti_kick",           "Anti-Kick"),
    discord.AuditLogAction.channel_create:       ("anti_ch_create",      "Anti-Channel Create"),
    discord.AuditLogAction.channel_delete:       ("anti_ch_delete",      "Anti-Channel Delete"),
    discord.AuditLogAction.channel_update:       ("anti_ch_update",      "Anti-Channel Update"),
    discord.AuditLogAction.role_create:          ("anti_role_create",    "Anti-Role Create"),
    discord.AuditLogAction.role_delete:          ("anti_role_delete",    "Anti-Role Delete"),
    discord.AuditLogAction.role_update:          ("anti_role_update",    "Anti-Role Update"),
    discord.AuditLogAction.member_role_update:   ("anti_role_give",      "Anti-Role Give (Dangerous)"),
    discord.AuditLogAction.guild_update:         ("anti_guild_update",   "Anti-Guild Update"),
    discord.AuditLogAction.webhook_create:       ("anti_webhook_create", "Anti-Webhook Create"),
    discord.AuditLogAction.webhook_delete:       ("anti_webhook_delete", "Anti-Webhook Delete"),
    discord.AuditLogAction.bot_add:              ("anti_bot_add",        "Anti-Bot Add"),
    discord.AuditLogAction.member_prune:         ("anti_prune",          "Anti-Prune Members"),
    discord.AuditLogAction.integration_create:   ("anti_integration",    "Anti-Integration"),
    discord.AuditLogAction.integration_update:   ("anti_integration",    "Anti-Integration"),
}

# [Speed] Voice Abuse actions ที่ต้องจับผ่าน on_audit_log_entry_create (ไม่ต้อง HTTP pull)
_VOICE_ABUSE_AUDIT_ACTIONS = {
    discord.AuditLogAction.member_update,
    discord.AuditLogAction.member_move,
    discord.AuditLogAction.member_disconnect,
}

# [Speed] record_action key map จาก feature_key
_FEATURE_RECORD_MAP = {
    "anti_ban":            "ban",
    "anti_kick":           "kick",
    "anti_ch_create":      "ch_create",
    "anti_ch_delete":      "ch_delete",
    "anti_role_create":    "role_create",
    "anti_role_delete":    "role_delete",
    "anti_role_give":      "role_give",
    "anti_webhook_create": "webhook",
    "anti_webhook_delete": "webhook",
    "anti_bot_add":        "bot_add",
    "anti_guild_update":   "guild_update",
}

@bot.event
async def on_audit_log_entry_create(entry: discord.AuditLogEntry):
    """
    [Session 7] ชั้นที่ 1 (Event-driven): รับ actor จาก Gateway โดยตรง
    ไม่มี HTTP round-trip → เร็วกว่า audit_logs query ~200-500ms
    ส่ง actor ให้ทั้งระบบ A (check_feature) และระบบ B (do_advanced_lockdown)
    [Speed] เพิ่ม: Voice Abuse + record_action ทุก action จัดการตรงนี้เลย
    """
    guild = entry.guild
    actor = entry.user
    if not guild or not actor or actor.bot:
        return

    # ── ข้ามถ้าเป็นบอทตัวเอง ──
    if bot.user and actor.id == bot.user.id:
        return

    try:
        # ── [Speed] Voice Abuse: จับจาก Gateway ตรงๆ ไม่ต้อง HTTP pull ──
        if entry.action in _VOICE_ABUSE_AUDIT_ACTIONS:
            asyncio.create_task(_handle_voice_abuse_entry(guild, actor, entry))

        mapping = _ACTION_FEATURE_MAP.get(entry.action)
        if not mapping:
            return

        feature_key, label = mapping
        cfg  = get_cfg(guild.id)
        feat = cfg.get(feature_key, {})
        if not feat.get("enabled"):
            return

        # ── ตรวจ whitelist ──
        member = guild.get_member(actor.id)
        if member and is_whitelisted(member, cfg):
            return

        # ── Anti-Channel Update: ข้ามถ้ากำลัง lockdown อยู่ ──
        if feature_key == "anti_ch_update":
            if cfg.get("_lockdown_state") or guild.id in bot.adv_lock_active:
                return

        # ── Anti-Role Update: ข้ามถ้า adv_lock กำลังทำงาน ──
        if feature_key == "anti_role_update":
            if guild.id in bot.adv_lock_active:
                return

        # ── Anti-Role Give: ตรวจเฉพาะยศที่มีสิทธิ์อันตราย ──
        if feature_key == "anti_role_give":
            after_member = guild.get_member(entry.target.id) if entry.target else None
            if after_member:
                added = [r for r in after_member.roles
                         if any(getattr(r.permissions, p, False) for p in DANGEROUS_PERMS)]
                if not added:
                    return
            if member and member.id == guild.me.id:
                return

        # [Session 7] ระบบ A: check_feature (ทั้ง normal และ advanced mode)
        # known_offender_id ส่งตรงๆ ไม่ต้องรอ audit log
        adv_enabled = cfg.get("advanced_mode", {}).get(feature_key, False)
        _detected_ms = int(time.time() * 1000)
        E_ARROW  = "⟫"
        E_SEP    = "─────────"
        E_DANGER = "🔴"
        E_BELL   = "🔔"
        E_ROLE   = "🏷️"
        E_SORT   = "▷"
        E_ALERT  = "🚨"
        if adv_enabled:
            asyncio.create_task(
                do_advanced_lockdown(guild, feature_key, cfg, known_offender_id=actor.id)
            )
            em = discord.Embed(
                title=f"{E_DANGER} {label} — โหมดจัดการขั้นสูง",
                color=0xa855f7,
            )
            em.description = (
                f"{E_ARROW} **ตรวจจับ actor จาก Gateway ทันที** (Event-driven)\n"
                f"{E_ARROW} **ผู้กระทำ:** {actor.mention if hasattr(actor, 'mention') else str(actor)} "
                f"`{actor}` (ID: `{actor.id}`)\n"
                f"{E_SEP}\n"
                f"{E_BELL} ปิดสิทธิ์ผู้ดูแลชั่วคราว — กำลังตรวจสอบ..."
            )
            em.add_field(
                name=f"{E_SORT} เวลาที่ตรวจพบ (ms)",
                value=f"`{_detected_ms} ms` (<t:{_detected_ms//1000}:T>)",
                inline=True,
            )
            em.add_field(name=f"{E_ROLE} Feature", value=f"`{feature_key}`", inline=True)
            em.set_footer(text=f"AdvancedMode ON | Actor: {actor} | Guild: {guild.id}")
            em.timestamp = datetime.now(timezone.utc)
            await send_log(guild, em)
        else:
            await check_feature(guild, actor, feature_key, label)

        # ── BIE: บันทึกและวิเคราะห์ทุก action ──────────────────────
        bie_ak = {
            "anti_ch_create": "ch_create", "anti_ch_delete": "ch_delete",
            "anti_role_create": "role_create", "anti_role_delete": "role_delete",
            "anti_role_give": "role_give", "anti_ban": "ban", "anti_kick": "kick",
            "anti_webhook_create": "webhook", "anti_webhook_delete": "webhook",
            "anti_bot_add": "bot_add", "anti_guild_update": "guild_update",
        }.get(feature_key)
        if bie_ak:
            bie_record(guild.id, actor.id, bie_ak)
            asyncio.create_task(bie_analyze(guild, actor.id, bie_ak))

        # ── [Speed] record_action: บันทึกทุก action ให้ Suspicious Tracker ──
        # เดิมไม่มีจุดนี้ → Suspicious Tracker ไม่ได้รับข้อมูลจาก anti_bot_add / anti_prune / anti_integration
        rec_key = _FEATURE_RECORD_MAP.get(feature_key)
        if rec_key:
            record_action(guild.id, actor.id, rec_key, f"via {feature_key}")

    except Exception as e:
        log.error(f"on_audit_log_entry_create [{entry.action}]: {e}")

# ══════════════════════════════════════════════════════════════════
#  VOICE ABUSE
# ══════════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════
#  VOICE ABUSE — on_voice_state_update()
#  ตรวจจับการย้าย/disconnect/mute คนใน voice channel ถี่เกินไป
#  ดึง Audit Log ใน background เพื่อหาว่าใครเป็นคนทำ action นั้น
#  ใช้ voice_track เป็น sliding-window แยกจาก spam tracker
#  VOICE_ABUSE_ACTIONS: member_update, member_move, member_disconnect
# ══════════════════════════════════════════════════════════════════
@bot.event
async def on_voice_state_update(member: discord.Member, before: discord.VoiceState, after: discord.VoiceState):
    # [Speed] Voice Abuse ย้ายไปจัดการใน on_audit_log_entry_create แล้ว (Gateway, ไม่ต้อง HTTP pull)
    # on_voice_state_update นี้เหลือไว้แค่เป็น hook ในกรณีที่ต้องการ log เพิ่มเติมในอนาคต
    pass

# ══════════════════════════════════════════════════════════════════
#  OTHER LOG EVENTS
# ══════════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════
#  OTHER LOG EVENTS — บันทึกเหตุการณ์ทั่วไปลง log channel (ไม่มีการลงโทษ)
#  on_message_delete  → log ข้อความที่ถูกลบ (ตัดที่ 500 ตัวอักษร)
#  on_message_edit    → log ข้อความก่อน/หลังแก้ไข (ตัดที่ 300 ตัวอักษร)
#  on_invite_create   → log ลิงก์เชิญใหม่ พร้อมผู้สร้างและวันหมดอายุ
# ══════════════════════════════════════════════════════════════════
async def _handle_voice_abuse_entry(guild: discord.Guild, actor: discord.Member | discord.User, entry: discord.AuditLogEntry):
    """[Speed] ตรวจ Voice Abuse จาก audit log entry โดยตรง ไม่ต้อง HTTP query ซ้ำ"""
    cfg = get_cfg(guild.id)
    va  = cfg.get("voiceabuse", {})
    if not va.get("enabled"):
        return
    try:
        if actor.bot or actor.id == guild.me.id:
            return
        actor_member = guild.get_member(actor.id)
        if actor_member is None:
            return
        if is_whitelisted(actor_member, cfg):
            return
        now      = time.time()
        interval = va.get("window", 10)
        limit    = va.get("limit", 5)
        track    = bot.voice_track[guild.id][actor.id]
        track    = [(a, t) for a, t in track if now - t < interval]
        track.append((str(entry.action), now))
        bot.voice_track[guild.id][actor.id] = track
        if len(track) >= limit:
            triggered_count = len(track)
            bot.voice_track[guild.id][actor.id] = []
            mute_min = va.get("mute_duration", 10)
            timeout_sec = mute_min * 60
            em = discord.Embed(
                title="🎙️ Voice Abuse",
                description=f"{actor_member.mention} ทำ voice action รัวๆ ({triggered_count}x ใน {interval}วิ)",
                color=0xf59e0b)
            await asyncio.gather(
                apply_punishment(guild, actor_member,
                    va.get("punishment", "timeout"),
                    f"Voice Abuse: {triggered_count} ครั้งใน {interval} วิ",
                    timeout_seconds=timeout_sec),
                send_log(guild, em),
                return_exceptions=True,
            )
    except Exception as e:
        log.error(f"_handle_voice_abuse_entry: {e}")

# ══════════════════════════════════════════════════════════════════
#  OTHER LOG EVENTS
# ══════════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════
#  OTHER LOG EVENTS — บันทึกเหตุการณ์ทั่วไปลง log channel (ไม่มีการลงโทษ)
#  on_message_delete  → log ข้อความที่ถูกลบ (ตัดที่ 500 ตัวอักษร)
#  on_message_edit    → log ข้อความก่อน/หลังแก้ไข (ตัดที่ 300 ตัวอักษร)
#  on_invite_create   → log ลิงก์เชิญใหม่ พร้อมผู้สร้างและวันหมดอายุ
# ══════════════════════════════════════════════════════════════════


@bot.event
async def on_message_delete(message: discord.Message):
    if message.author.bot or not message.guild:
        return
    E_ARROW = "⟫"
    E_SEP   = "─────────"
    E_WARN  = "⚠️"
    E_CANCEL= "❌"
    now_ms  = int(time.time() * 1000)
    em = discord.Embed(
        title=f"{E_CANCEL} ลบข้อความ",
        color=0xd29922,
    )
    em.description = (
        f"{E_ARROW} **ผู้ส่ง:** {message.author.mention} `{message.author}` (ID: `{message.author.id}`)\n"
        f"{E_ARROW} **ห้อง:** {message.channel.mention} (`{message.channel.name}`)\n"
        f"{E_SEP}\n"
        f"{E_WARN} **เนื้อหา:**\n>>> {message.content[:450] or '*(ไม่มีข้อความ)*'}"
    )
    if message.attachments:
        em.add_field(
            name="📎 ไฟล์แนบ",
            value="\n".join(f"`{a.filename}`" for a in message.attachments),
            inline=False,
        )
    em.add_field(name="🕐 เวลา (ms)", value=f"`{now_ms}`", inline=True)
    em.add_field(name="📅 Discord timestamp", value=f"<t:{now_ms//1000}:F>", inline=True)
    em.set_footer(text=f"Message ID: {message.id} | Guild: {message.guild.id}")
    em.timestamp = datetime.now(timezone.utc)
    await send_log(message.guild, em, "message_delete")
@bot.event
async def on_message_edit(before: discord.Message, after: discord.Message):
    if before.author.bot or before.content == after.content or not before.guild:
        return
    E_ARROW = "⟫"
    E_SEP   = "─────────"
    E_WARN  = "⚠️"
    E_SORT  = "▷"
    now_ms  = int(time.time() * 1000)
    em = discord.Embed(
        title=f"{E_WARN} แก้ไขข้อความ",
        color=0x5865F2,
    )
    em.description = (
        f"{E_ARROW} **ผู้ส่ง:** {before.author.mention} `{before.author}` (ID: `{before.author.id}`)\n"
        f"{E_ARROW} **ห้อง:** {before.channel.mention} (`{before.channel.name}`)\n"
        f"{E_SEP}"
    )
    em.add_field(name=f"{E_SORT} ก่อนแก้ไข", value=f">>> {before.content[:280] or '-'}", inline=False)
    em.add_field(name=f"{E_SORT} หลังแก้ไข", value=f">>> {after.content[:280] or '-'}", inline=False)
    em.add_field(name="🔗 ลิงก์", value=f"[กดดูข้อความ]({after.jump_url})", inline=True)
    em.add_field(name="🕐 เวลา (ms)", value=f"`{now_ms}`", inline=True)
    em.add_field(name="📅 Discord timestamp", value=f"<t:{now_ms//1000}:F>", inline=True)
    em.set_footer(text=f"Message ID: {after.id} | Guild: {before.guild.id}")
    em.timestamp = datetime.now(timezone.utc)
    await send_log(before.guild, em, "message_edit")
@bot.event
async def on_invite_create(invite: discord.Invite):
    if not invite.guild:
        return
    E_ARROW = "⟫"
    E_SEP   = "─────────"
    E_BELL  = "🔔"
    E_ROLE  = "🏷️"
    now_ms  = int(time.time() * 1000)
    em = discord.Embed(
        title=f"{E_BELL} สร้างลิงก์เชิญใหม่",
        color=0x3b82f6,
    )
    inviter = invite.inviter
    em.description = (
        f"{E_ARROW} **สร้างโดย:** {inviter.mention if inviter else 'Integration/System'} "
        f"`{inviter}` (ID: `{inviter.id if inviter else '-'}`)"f"\n"
        f"{E_ARROW} **ลิงก์:** `{invite.url}`\n"
        f"{E_SEP}"
    )
    em.add_field(
        name=f"{E_ROLE} รายละเอียด",
        value=(
            f"**Code:** `{invite.code}`\n"
            f"**หมดอายุ:** {f'{invite.max_age//3600} ชม.' if invite.max_age else 'ไม่มีกำหนด'}\n"
            f"**ใช้ได้:** {f'{invite.max_uses} ครั้ง' if invite.max_uses else 'ไม่จำกัด'}\n"
            f"**ชั่วคราว:** {'ใช่' if invite.temporary else 'ไม่ใช่'}"
        ),
        inline=True,
    )
    em.add_field(name="🕐 เวลา (ms)", value=f"`{now_ms}`", inline=True)
    em.add_field(name="📅 Discord timestamp", value=f"<t:{now_ms//1000}:F>", inline=True)
    em.set_footer(text=f"Guild: {invite.guild.id}")
    em.timestamp = datetime.now(timezone.utc)
    await send_log(invite.guild, em, "invite_create")

# ══════════════════════════════════════════════════════════════════
#  ANTI USER-INSTALLABLE APPS
#  ตรวจจับ slash command ที่มาจากบอทที่ user ติดตั้งในโปรไฟล์ตัวเอง
#  (User-Installed / User-App) แล้วเข้ามาใช้งานใน server นี้
#
#  วิธีตรวจ: interaction.data["integration_type"] == 1
#    0 = Guild Install (บอทถูกเชิญเข้า server ตามปกติ)
#    1 = User Install  (บอทอยู่ในโปรไฟล์ user — ผิดที่)
#
#  Action ที่ทำได้:
#    delete  — ลบ interaction response ทันที + แจ้ง ephemeral
#    warn    — แจ้ง ephemeral เตือน user
#    timeout — timeout user ตาม timeout_seconds
# ══════════════════════════════════════════════════════════════════
@bot.event
async def on_interaction(interaction: discord.Interaction):
    """ตรวจ User-Installed App ทุก interaction ที่เกิดขึ้นใน guild"""
    # ต้องอยู่ใน guild และเป็น application command
    if not interaction.guild or not interaction.data:
        return

    cfg  = get_cfg(interaction.guild_id)
    feat = cfg.get("anti_user_install", {})
    if not feat.get("enabled"):
        return

    # ตรวจ integration_type: 1 = User Install
    integration_type = interaction.data.get("integration_type", 0)
    if integration_type != 1:
        return  # Guild-installed bot ปกติ ไม่แตะ

    user   = interaction.user
    app_id = str(interaction.application_id or "")

    # ── Whitelist checks ──
    wl_users = [str(u) for u in feat.get("whitelist_users", [])]
    wl_apps  = [str(a) for a in feat.get("whitelist_apps", [])]
    if str(user.id) in wl_users or app_id in wl_apps:
        return

    # ── ป้องกัน owner + whitelisted member ──
    member = interaction.guild.get_member(user.id)
    if member:
        if is_whitelisted(member, cfg):
            return
        if interaction.guild.owner_id == user.id:
            return

    action          = feat.get("action", "delete")
    timeout_seconds = int(feat.get("timeout_seconds", 300))
    cmd_name        = interaction.data.get("name", "unknown")
    app_name        = ""
    try:
        # พยายามดึงชื่อ application (อาจไม่มีเสมอ)
        app_name = str(interaction.data.get("application_id", app_id))
    except Exception:
        app_name = app_id

    log.warning(
        f"[UserInstall] {user} ({user.id}) ใช้ /{cmd_name} "
        f"(app={app_name}) ใน {interaction.guild.name} — action={action}"
    )

    # ── ส่ง log ──
    if feat.get("log_to_channel", True):
        em = discord.Embed(
            title="🚫 User-Installed App ถูกตรวจพบ",
            color=0xff4757,
            description=(
                f"**User:** {user.mention} (`{user.id}`)\n"
                f"**Command:** `/{cmd_name}`\n"
                f"**App ID:** `{app_id}`\n"
                f"**Action:** `{action}`"
            )
        )
        em.set_footer(text="Anti User-Install Protection")
        await send_log(interaction.guild, em)
        await bot_log(interaction.guild,
                      "🚫 User-Install App ตรวจพบ",
                      f"{user.mention} ใช้ `/{cmd_name}` ผ่าน User-Installed Bot (app={app_id}) → {action}")

    # ── ทำ action ──
    warn_msg = (
        f"🚫 **ACCESS DENIED — User-Installed App Detected**\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"**Server:** {interaction.guild.name}\n"
        f"**Command:** `/{cmd_name}`\n"
        f"**Reason:** This server does **not** allow bots installed via user profiles.\n\n"
        f"⚠️ Your action has been **blocked and logged**.\n"
        f"If you believe this is a mistake, contact a server administrator."
    )

    if action == "delete":
        try:
            await interaction.response.send_message(warn_msg, ephemeral=True)
        except Exception:
            pass
        # ลบ response ที่บอท User-Install ตอบกลับมา
        try:
            await asyncio.sleep(0.5)
            await interaction.delete_original_response()
        except Exception:
            pass
        # บันทึก action
        record_action(interaction.guild_id, user.id, "msg_spam",
                      f"User-Install App /{cmd_name} (app={app_id})")

    elif action == "warn":
        try:
            await interaction.response.send_message(warn_msg, ephemeral=True)
        except Exception:
            pass

    elif action == "timeout":
        try:
            await interaction.response.send_message(warn_msg, ephemeral=True)
        except Exception:
            pass
        # ลบ response ที่บอท User-Install ตอบกลับมา
        try:
            await asyncio.sleep(0.5)
            await interaction.delete_original_response()
        except Exception:
            pass
        if member:
            try:
                until = discord.utils.utcnow() + __import__("datetime").timedelta(seconds=timeout_seconds)
                await member.timeout(until, reason=f"Anti User-Install: /{cmd_name}")
                record_action(interaction.guild_id, user.id, "msg_spam",
                              f"User-Install App /{cmd_name} → timeout {timeout_seconds}s")
            except Exception as e:
                log.error(f"[UserInstall] timeout failed: {e}")


# ══════════════════════════════════════════════════════════════════
#  COMMANDS HELPERS
# ══════════════════════════════════════════════════════════════════
async def cmd_init_blacklist(message: discord.Message):
    guild = message.guild
    cfg   = get_cfg(guild.id)
    existing_id = cfg.get("blacklist_role_id")
    if existing_id:
        existing = guild.get_role(int(existing_id))
        if existing:
            await message.reply(f"✅ ยศ Blacklist มีอยู่แล้ว: **{existing.name}**", delete_after=10)
            return
    try:
        bl_role = await guild.create_role(name="⛔ Blacklist", color=discord.Color.from_rgb(139, 0, 0),
                                          reason="Security Bot: สร้างยศ Blacklist")
        for channel in guild.channels:
            try:
                await channel.set_permissions(bl_role, view_channel=False, send_messages=False,
                                              connect=False, speak=False, reason="Blacklist role")
            except Exception:
                pass
        cfg["blacklist_role_id"] = bl_role.id
        await save_guild_data(guild.id)
        await message.reply(f"✅ สร้างยศ **{bl_role.name}** แล้ว\n🆔 Role ID: `{bl_role.id}`", delete_after=15)
    except Exception as e:
        await message.reply(f"❌ สร้างยศไม่ได้: {e}", delete_after=10)

async def cmd_whitelist(message: discord.Message, cfg: dict):
    parts = message.content.strip().split()
    wl = cfg.setdefault("whitelist", {"users": [], "roles": []})
    if len(parts) < 2:
        await message.reply(
            "📋 วิธีใช้:\n"
            "`!whitelist user @สมาชิก` — เพิ่มสมาชิก\n"
            "`!whitelist role @ยศ` — เพิ่มยศ\n"
            "`!whitelist remove user @สมาชิก` — ลบสมาชิก\n"
            "`!whitelist remove role @ยศ` — ลบยศ\n"
            "`!whitelist list` — ดูรายชื่อ",
            delete_after=20)
        return
    sub = parts[1].lower()
    if sub == "list":
        user_mentions = [f"<@{uid}>" for uid in wl.get("users", [])]
        role_mentions = [f"<@&{rid}>" for rid in wl.get("roles", [])]
        txt = f"📋 **Whitelist**\n👤 สมาชิก: {', '.join(user_mentions) or '-'}\n🏷️ ยศ: {', '.join(role_mentions) or '-'}"
        await message.reply(txt, delete_after=20)
        return
    removing = (sub == "remove")
    if removing and len(parts) >= 3:
        sub = parts[2].lower()
    if sub == "user":
        if not message.mentions:
            await message.reply("❌ กรุณาแท็กสมาชิก", delete_after=5); return
        for m in message.mentions:
            if removing:
                if m.id in wl["users"]: wl["users"].remove(m.id)
                await message.reply(f"✅ ลบ {m.mention} ออกจาก whitelist", delete_after=5)
            else:
                if m.id not in wl["users"]: wl["users"].append(m.id)
                await message.reply(f"✅ เพิ่ม {m.mention} เข้า whitelist", delete_after=5)
    elif sub == "role":
        if not message.role_mentions:
            await message.reply("❌ กรุณาแท็กยศ", delete_after=5); return
        for r in message.role_mentions:
            if removing:
                if r.id in wl["roles"]: wl["roles"].remove(r.id)
                await message.reply(f"✅ ลบยศ {r.mention} ออกจาก whitelist", delete_after=5)
            else:
                if r.id not in wl["roles"]: wl["roles"].append(r.id)
                await message.reply(f"✅ เพิ่มยศ {r.mention} เข้า whitelist", delete_after=5)
    else:
        await message.reply("❌ คำสั่งไม่ถูกต้อง", delete_after=5); return
    await save_guild_data(message.guild.id)

# ══════════════════════════════════════════════════════════════════
#  WEB API — REST endpoints สำหรับ Dashboard
#  ทุก endpoint ยกเว้น /api/options และ /api/verify ต้องส่ง ?token= มาด้วย
#  jres() เป็น helper สร้าง JSON response พร้อม CORS header
#  CORS เปิดให้ทุก origin เข้าได้ (Dashboard อยู่ domain เดียวกับ API)
#
#  api_options      — ตอบ preflight CORS request (OPTIONS method)
#  api_verify       — ตรวจ token และคืนข้อมูล guild (guild_id, guild_name)
#  api_get_config   — GET config ทั้งหมดของ guild นั้น
#  api_post_config  — POST config ใหม่ (deep merge), จัดการ lockdown toggle อัตโนมัติ
#  api_stats        — ข้อมูลสถิติ server (จำนวน member, channel, role, สถานะ raid/lockdown)
#  api_logs         — audit log ย้อนหลัง (in-memory ก่อน, fallback Discord audit log)
#  api_lockdown     — สั่ง do_lockdown(enable=True/False) จาก Dashboard
#  api_advanced_manage — เปิด/ปิด advanced_mode ของ feature นั้น ๆ
#  api_roles        — รายชื่อ role ทั้งหมดใน guild (เรียงตาม position)
#  api_members      — รายชื่อ member (ค้นหาได้ด้วย ?q=, คืนสูงสุด 25 คน)
#  api_member_detail — ข้อมูล member รายบุคคล + exemption settings
#  api_save_member_exemptions — บันทึก per-member exemption
#  api_role_channels — permission ของ role นั้นในทุก channel
#  api_suspicious_alerts — alerts จาก Suspicious Behavior Tracker (+ member info)
#  api_mark_alert_read   — mark alert ว่าอ่านแล้ว
#  api_member_actions    — history action ของ member คนนั้น (สูงสุด 100 รายการ)
#  api_create_log_channel / api_delete_log_channel — จัดการห้อง log
#  api_role_manager_get / api_role_manager_post — จัดการ Role Manager config
# ══════════════════════════════════════════════════════════════════
CORS = {"Access-Control-Allow-Origin": "*"}

def jres(data, status=200):
    return web.Response(
        text=json.dumps(data, ensure_ascii=False),
        status=status,
        headers={**CORS, "Content-Type": "application/json"},
    )

# ══════════════════════════════════════════════════════════════════
#  API: Anti User-Installable Apps
# ══════════════════════════════════════════════════════════════════
async def api_user_install_get(req: web.Request) -> web.Response:
    """GET /api/user-install — ดึง config anti_user_install"""
    d = verify_token(req.rel_url.query.get("token", ""))
    if not d: return jres({"error": "Unauthorized"}, 401)
    cfg  = get_cfg(d["guild_id"])
    feat = cfg.get("anti_user_install", {
        "enabled": False, "action": "delete",
        "timeout_seconds": 300, "log_to_channel": True,
        "whitelist_users": [], "whitelist_apps": [],
    })
    return jres(feat)


async def api_user_install_post(req: web.Request) -> web.Response:
    """POST /api/user-install — บันทึก config anti_user_install"""
    d = verify_token(req.rel_url.query.get("token", ""))
    if not d: return jres({"error": "Unauthorized"}, 401)
    try:
        body = await req.json()
    except Exception:
        return jres({"error": "invalid json"}, 400)

    gid = d["guild_id"]
    cfg = get_cfg(gid)
    feat = cfg.setdefault("anti_user_install", {})
    feat["enabled"]          = bool(body.get("enabled", False))
    feat["action"]           = body.get("action", "delete")
    feat["timeout_seconds"]  = int(body.get("timeout_seconds", 300))
    feat["log_to_channel"]   = bool(body.get("log_to_channel", True))
    feat["whitelist_users"]  = [str(u) for u in body.get("whitelist_users", [])]
    feat["whitelist_apps"]   = [str(a) for a in body.get("whitelist_apps", [])]
    await save_guild_data(gid)
    return jres({"ok": True})


async def api_options(req):
    return web.Response(status=200, headers={
        **CORS,
        "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
    })

async def api_verify(req):
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"valid": False, "message": "รหัสไม่ถูกต้องหรือหมดอายุ"}, 401)
    return jres({"valid": True, "guild_id": str(d["guild_id"]), "guild_name": d["guild_name"]})

async def api_get_config(req):
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    return jres(get_cfg(d["guild_id"]))

async def api_post_config(req):
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    try:
        new = await req.json()
        cfg = get_cfg(d["guild_id"])
        def _deep_merge(dst, src):
            for k, v in src.items():
                if isinstance(v, dict) and isinstance(dst.get(k), dict):
                    _deep_merge(dst[k], v)
                else:
                    dst[k] = v
        _deep_merge(cfg, new)
        # Handle lockdown toggle
        guild = bot.get_guild(d["guild_id"])
        if guild:
            ld = cfg.get("server_lockdown", {})
            ld_active = bool(get_cfg(guild.id).get("_lockdown_state"))
            if ld.get("enabled") and not ld_active:
                await do_lockdown(guild, True)   # [Audit Session 4+5] แก้: create_task → await ป้องกัน race condition
            elif not ld.get("enabled") and ld_active:
                await do_lockdown(guild, False)  # [Audit Session 4+5] แก้: create_task → await ป้องกัน race condition
        await save_guild_data(d["guild_id"])
        return jres({"success": True})
    except Exception as e:
        return jres({"error": str(e)}, 400)

async def api_stats(req):
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    guild = bot.get_guild(d["guild_id"])
    if not guild: return jres({"error": "guild not found"}, 404)
    online = sum(1 for m in guild.members
                 if not m.bot and getattr(m, "status", discord.Status.offline) != discord.Status.offline)
    return jres({
        "guild_name":    guild.name,
        "server_id":     str(guild.id),
        "member_count":  guild.member_count,
        "online_count":  online,
        "channel_count": len(guild.channels),
        "role_count":    len(guild.roles),
        "icon_url":      str(guild.icon.url) if guild.icon else "",
        "banner_url":    str(guild.banner.url) + "?size=1024" if guild.banner else "",  # [Session 5] ภาพพื้นหลัง server
        "splash_url":    str(guild.splash.url) + "?size=1024" if guild.splash else "",  # [Session 5] invite splash ใช้เป็น fallback ถ้าไม่มี banner
        "in_lockdown":   bool(get_cfg(guild.id).get("_lockdown_state")),
        "raid_mode":     guild.id in bot.raid_mode,
    })

async def api_logs(req):
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    guild = bot.get_guild(d["guild_id"])
    if not guild: return jres({"error": "guild not found"}, 404)
    # ── ดึง internal audit log ทั้งหมด (สูงสุด 200 รายการ) ──
    internal = list(bot.audit_log.get(d["guild_id"], []))
    if internal:
        return jres(internal[:100])
    # ── fallback: ดึง Discord audit logs เมื่อยังไม่มี internal ──
    logs = []
    try:
        async for entry in guild.audit_logs(limit=50):
            logs.append({
                "action":    str(entry.action).replace("AuditLogAction.", ""),
                "user":      str(entry.user),
                "target":    str(entry.target) if entry.target else "-",
                "reason":    entry.reason or "-",
                "timestamp": entry.created_at.isoformat(),
            })
    except Exception as e:
        return jres({"error": str(e)}, 500)
    return jres(logs)

async def api_channels_validate(req):
    """GET /api/channels/validate — ตรวจสอบห้องใน config ว่ายังมีอยู่จริงใน Discord ไหม"""
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    guild = bot.get_guild(d["guild_id"])
    if not guild: return jres({"error": "guild not found"}, 404)
    cfg = get_cfg(d["guild_id"])
    missing = []
    # ตรวจ log_channel_id หลัก
    main_id = cfg.get("log_channel_id")
    if main_id and not guild.get_channel(int(main_id)):
        missing.append({"type": "log_channel_id", "label": "Log Channel หลัก", "id": str(main_id)})
    # ตรวจ log_channels แต่ละประเภท
    log_ch_labels = {
        "member_join":"Log เข้าร่วม","member_leave":"Log ออกจาก","member_ban":"Log แบน",
        "member_kick":"Log เตะ","message_delete":"Log ลบข้อความ","message_edit":"Log แก้ข้อความ",
        "role_update":"Log ยศ","channel_update":"Log ห้อง","voice_update":"Log เสียง","invite_create":"Log ลิงก์เชิญ",
    }
    for k, label in log_ch_labels.items():
        ch_id = cfg.get("log_channels", {}).get(k)
        if ch_id and not guild.get_channel(int(ch_id)):
            missing.append({"type": f"log_channels.{k}", "label": label, "id": str(ch_id)})
    return jres({"missing": missing})

async def api_channels_clear(req):
    """POST /api/channels/clear — ลบ channel ที่หายไปออกจาก config"""
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    try:
        body = await req.json()
        cfg  = get_cfg(d["guild_id"])
        for item in body.get("items", []):
            tp = item.get("type", "")
            if tp == "log_channel_id":
                cfg["log_channel_id"] = None
            elif tp.startswith("log_channels."):
                k = tp.split(".", 1)[1]
                if "log_channels" in cfg and k in cfg["log_channels"]:
                    cfg["log_channels"][k] = None
        await save_guild_data(d["guild_id"])
        return jres({"success": True})
    except Exception as e:
        return jres({"error": str(e)}, 400)

async def api_create_log_channel(req):
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    guild = bot.get_guild(d["guild_id"])
    if not guild: return jres({"error": "guild not found"}, 404)
    try:
        body = await req.json()
        log_type = body.get("log_type", "")
        valid_types = [
            # ห้องเดิม 10
            "member_join","member_leave","member_ban","member_kick",
            "message_delete","message_edit","role_update","channel_update",
            "voice_update","invite_create",
            # ห้องใหม่ 30
            "member_timeout","member_unban","member_nickname",
            "member_role_add","member_role_remove","member_quarantine",
            "channel_create","channel_delete","channel_permission",
            "role_create","role_delete","role_permission",
            "webhook_create","webhook_delete",
            "emoji_create","emoji_delete",
            "sticker_create","sticker_delete",
            "thread_create","thread_delete","thread_update",
            "voice_join","voice_leave","voice_move","voice_mute",
            "invite_delete","server_update","automod_action",
            "spam_detect","raid_detect","bot_added",
        ]
        if log_type not in valid_types:
            return jres({"error": "invalid log_type"}, 400)
        ch = await create_log_channel(guild, log_type)
        if not ch:
            return jres({"error": "สร้างห้องไม่ได้ ตรวจสอบ permission"}, 500)
        cfg = get_cfg(guild.id)
        cfg.setdefault("log_channels", {})[log_type] = ch.id
        await save_guild_data(guild.id)
        return jres({"success": True, "channel_id": str(ch.id), "channel_name": ch.name})
    except Exception as e:
        return jres({"error": str(e)}, 400)

async def api_delete_log_channel(req):
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    try:
        body = await req.json()
        log_type = body.get("log_type", "")
        cfg = get_cfg(d["guild_id"])
        if "log_channels" in cfg and log_type in cfg["log_channels"]:
            cfg["log_channels"][log_type] = None
        await save_guild_data(d["guild_id"])
        return jres({"success": True})
    except Exception as e:
        return jres({"error": str(e)}, 400)

# ══════════════════════════════════════════════════════════════════
#  API: Bot Action Log Channel — สร้าง/ลบ 🤖・bot-action-log
# ══════════════════════════════════════════════════════════════════
async def api_create_bot_action_log(req):
    """POST /api/bot-action-log/create — สร้างห้อง bot-action-log"""
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    guild = bot.get_guild(d["guild_id"])
    if not guild: return jres({"error": "guild not found"}, 404)
    try:
        ch = await _create_bot_action_log(guild)
        if not ch:
            return jres({"error": "สร้างห้องไม่ได้ ตรวจสอบ permission"}, 500)
        cfg = get_cfg(guild.id)
        cfg.setdefault("log_channels", {})["bot_action_log"] = ch.id
        await save_guild_data(guild.id)
        return jres({"success": True, "channel_id": str(ch.id), "channel_name": ch.name})
    except Exception as e:
        return jres({"error": str(e)}, 400)

async def api_delete_bot_action_log(req):
    """POST /api/bot-action-log/delete — ถอด bot-action-log ออกจาก config (ไม่ลบห้องจริง)"""
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    try:
        cfg = get_cfg(d["guild_id"])
        cfg.setdefault("log_channels", {})["bot_action_log"] = None
        await save_guild_data(d["guild_id"])
        return jres({"success": True})
    except Exception as e:
        return jres({"error": str(e)}, 400)

# ══════════════════════════════════════════════════════════════════
#  API: Honeypot Channel — สร้าง/ลบ 🍯・honeypot
#  ห้องหลอกล่อ: มองเห็นได้สำหรับทุกคน แต่ห้ามส่งข้อความ
#  ใครก็ตามที่ส่งข้อความ/เข้า voice จะถูกบันทึกและแจ้งเตือนทันที
# ══════════════════════════════════════════════════════════════════
async def _create_honeypot_channel(guild: discord.Guild) -> discord.TextChannel | None:
    """สร้างห้อง honeypot — มองเห็นได้แต่ส่งไม่ได้, ใครส่งแจ้งเตือนทันที"""
    for ch in guild.text_channels:
        if ch.name == HONEYPOT_CH_NAME:
            return ch
    try:
        category = discord.utils.get(guild.categories, name="SECURITY LOGS")
        if not category:
            category = await guild.create_category("SECURITY LOGS", reason="Security Bot: สร้าง log category")
        ow = {
            guild.default_role: discord.PermissionOverwrite(
                read_messages=True,
                send_messages=False,   # มองเห็นแต่ส่งไม่ได้
                connect=False,
            ),
            guild.me: discord.PermissionOverwrite(
                read_messages=True, send_messages=True, manage_messages=True,
            ),
        }
        ch = await guild.create_text_channel(
            HONEYPOT_CH_NAME,
            category=category,
            overwrites=ow,
            topic="⚠️ ห้องทดสอบระบบ — ห้ามส่งข้อความ",
            reason="Security Bot: สร้างห้อง Honeypot",
        )
        log.info(f"✅ สร้างห้อง {HONEYPOT_CH_NAME} ใน {guild.name}")
        return ch
    except Exception as e:
        log.error(f"❌ สร้าง honeypot ไม่ได้: {e}")
        return None

async def api_create_honeypot(req):
    """POST /api/honeypot/create — สร้างห้อง honeypot"""
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    guild = bot.get_guild(d["guild_id"])
    if not guild: return jres({"error": "guild not found"}, 404)
    try:
        ch = await _create_honeypot_channel(guild)
        if not ch:
            return jres({"error": "สร้างห้องไม่ได้ ตรวจสอบ permission"}, 500)
        cfg = get_cfg(guild.id)
        cfg.setdefault("log_channels", {})["honeypot"] = ch.id
        await save_guild_data(guild.id)
        return jres({"success": True, "channel_id": str(ch.id), "channel_name": ch.name})
    except Exception as e:
        return jres({"error": str(e)}, 400)

async def api_delete_honeypot(req):
    """POST /api/honeypot/delete — ถอด honeypot ออกจาก config"""
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    try:
        cfg = get_cfg(d["guild_id"])
        cfg.setdefault("log_channels", {})["honeypot"] = None
        await save_guild_data(d["guild_id"])
        return jres({"success": True})
    except Exception as e:
        return jres({"error": str(e)}, 400)

async def api_roles(req):
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    guild = bot.get_guild(d["guild_id"])
    if not guild: return jres({"error": "guild not found"}, 404)
    roles = [
        {"id": str(r.id), "name": r.name, "color": str(r.color), "position": r.position}
        for r in sorted(guild.roles, key=lambda r: -r.position)
        if r.name != "@everyone"
    ]
    return jres(roles)

async def api_members(req):
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    guild = bot.get_guild(d["guild_id"])
    if not guild: return jres({"error": "guild not found"}, 404)
    query = req.rel_url.query.get("q", "").lower().strip()
    members = []
    for m in guild.members:
        if m.bot:
            continue
        if query:
            # Search by ID, global name, display name (nickname)
            if not (
                query in str(m.id) or
                query in m.name.lower() or
                query in (m.display_name or "").lower() or
                query in (m.global_name or "").lower()
            ):
                continue
        members.append({
            "id":           str(m.id),
            "name":         m.name,
            "display_name": m.display_name,
            "global_name":  m.global_name or m.name,
            "avatar":       str(m.display_avatar.url),
        })
        if len(members) >= 25:
            break
    return jres(members)

# ══════════════════════════════════════════════════════════════════
#  ADVANCED MANAGE / ADVANCED LOCKDOWN — do_advanced_lockdown()
#  โหมดป้องกันขั้นสูง ทำงาน 5 ขั้นตอนในลำดับที่ชัดเจน:
#
#  STEP 1: หา role เป้าหมายที่ต้องปิด
#    - ถ้า Role Manager ตั้งค่า dangerous_roles ไว้ → ใช้ list นั้นโดยตรง (เร็ว)
#    - ถ้าไม่ได้ตั้ง → auto-detect ทุก role ที่มี permission อันตราย (fallback)
#    - ข้าม role ที่สูงกว่าบอท, exempt_roles, member_roles
#
#  STEP 2: ปิด permissions ของ role เป้าหมายทั้งหมดทันที (parallel)
#    - บันทึก permissions เดิมลง cfg["_adv_lock_state"] และ bot.adv_lock_state
#
#  STEP 3: ระบุผู้กระทำ
#    - ใช้ known_offender_id ที่ส่งมาจาก check_feature() โดยตรง (เร็ว)
#    - fallback: ดึง Audit Log และหาคนที่ทำ action นั้นบ่อยที่สุดใน window
#
#  STEP 4: ลงโทษผู้กระทำตาม punishment ที่ตั้งไว้ใน feature config
#
#  STEP 5 (finally): คืน permissions ทุก role กลับเสมอ แม้จะเกิด error
#    - ล้าง adv_lock_state และ adv_lock_active
#
#  ป้องกัน double-run ด้วย adv_lock_active set
#  ADV_LOCK_PERMS: list สิทธิ์ที่ถือว่า "อันตราย" และควรปิดระหว่างตรวจสอบ
# ══════════════════════════════════════════════════════════════════

# permission ที่ถือว่าเป็น "ยศผู้ดูแล"
ADV_LOCK_PERMS = [
    "administrator",
    "manage_guild",
    "manage_roles",
    "manage_channels",
    "ban_members",
    "kick_members",
    "manage_webhooks",
    "mention_everyone",
    "manage_messages",
    "manage_nicknames",
    "mute_members",
    "deafen_members",
    "move_members",
]

def _role_is_admin_like(role: discord.Role) -> bool:
    """คืน True ถ้า role มี permission ผู้ดูแลอย่างน้อย 1 ข้อ"""
    for perm in ADV_LOCK_PERMS:
        if getattr(role.permissions, perm, False):
            return True
    return False

async def do_advanced_lockdown(guild: discord.Guild, feature_key: str, cfg: dict,
                               known_offender_id: int | None = None):
    """
    โหมดตรวจจับขั้นสูง:
    1. จำ permissions เดิมของทุก role ที่เป็น admin-like
    2. ปิด permissions ทั้งหมดของ role เหล่านั้นทันที
    3. ใช้ known_offender_id (ที่รู้อยู่แล้ว) → ลงโทษทันที; fallback ดึง Audit Log
    4. ลงโทษคนผิดตาม feature_key
    5. คืน permissions ทุก role กลับเหมือนเดิม
    """
    guild_id = guild.id

    # ── ถ้า advanced lock กำลังทำงานอยู่ → ไม่รันซ้ำ ──
    if guild_id in bot.adv_lock_active:
        log.warning(f"[AdvLock] {guild.name}: already running, skip")
        return

    bot.adv_lock_active.add(guild_id)
    log.info(f"[AdvLock] {guild.name}: เริ่มโหมดจัดการขั้นสูง (feature={feature_key})")

    saved_perms: dict = {}  # role_id → discord.Permissions (ค่าเดิม)

    try:
        # ── STEP 1: หา role ที่ต้องปิด ──
        bot_member = guild.get_member(bot.user.id)
        bot_top    = bot_member.top_role.position if bot_member else 9999

        rm          = cfg.get("role_manager", {})
        danger_ids  = set(int(x) for x in rm.get("dangerous_roles", []) if x)
        exempt_ids  = set(int(x) for x in rm.get("exempt_roles",    []) if x)
        member_ids  = set(int(x) for x in rm.get("member_roles",    []) if x)

        target_roles = []
        if danger_ids:
            # ⚡ โหมดเร็ว: ยิงตรงแค่ role ที่ตั้งไว้ใน Role Manager
            log.info(f"[AdvLock] {guild.name}: ใช้ Role Manager ({len(danger_ids)} role)")
            for role in guild.roles:
                if role.id not in danger_ids:
                    continue
                if role.position >= bot_top:
                    log.warning(f"[AdvLock] ข้าม {role.name}: สูงกว่าบอท")
                    continue
                target_roles.append(role)
        else:
            # 🔄 โหมด fallback: วน loop ทุก role (พฤติกรรมเดิม)
            log.info(f"[AdvLock] {guild.name}: Role Manager ยังไม่ตั้งค่า — ใช้โหมด auto-detect")
            for role in guild.roles:
                if role.name == "@everyone":
                    continue
                if role.id in exempt_ids or role.id in member_ids:
                    continue
                if role.position >= bot_top:
                    continue
                if _role_is_admin_like(role):
                    target_roles.append(role)

        if not target_roles:
            log.info(f"[AdvLock] {guild.name}: ไม่พบ role ผู้ดูแลที่สามารถแก้ไขได้")
            bot.adv_lock_active.discard(guild_id)
            return

        # ── STEP 2: บันทึก permissions เดิม แล้วปิดทุกอย่าง ──
        log.info(f"[AdvLock] {guild.name}: ปิด permissions {len(target_roles)} role")
        tasks_disable = []
        for role in target_roles:
            saved_perms[role.id] = role.permissions  # จำไว้
            zero_perms = discord.Permissions.none()
            tasks_disable.append(role.edit(permissions=zero_perms, reason="[AdvLock] ปิดชั่วคราว — กำลังตรวจสอบ"))

        # ปิดทุก role พร้อมกัน (parallel)
        results = await asyncio.gather(*tasks_disable, return_exceptions=True)
        for i, res in enumerate(results):
            if isinstance(res, Exception):
                log.warning(f"[AdvLock] ปิด role {target_roles[i].name} ไม่ได้: {res}")

        # บันทึก state → เก็บใน cfg (serialize permissions value เป็น int)
        cfg["_adv_lock_state"] = {str(rid): p.value for rid, p in saved_perms.items()}
        bot.adv_lock_state[guild_id] = saved_perms  # keep in-memory reference too
        # [Speed] ลบ save_guild_data() ออกจาก critical path — ไม่ควร await I/O ระหว่าง lockdown
        # auto_save จะบันทึกให้ทุก 5 นาทีอยู่แล้ว หรือ save หลัง finally ถ้าจำเป็น

        # แจ้ง log channel
        _ms_adv = int(time.time() * 1000)
        E_ARROW  = "⟫"
        E_SEP    = "─────────"
        E_DANGER = "🔴"
        E_BELL   = "🔔"
        E_ALERT  = "🚨"
        E_SORT   = "▷"
        E_ROLE   = "🏷️"
        em_start = discord.Embed(title=f"{E_DANGER} จัดการขั้นสูง — เริ่มทำงาน", color=0xff4757)
        em_start.description = (
            f"{E_ARROW} ปิดสิทธิ์ผู้ดูแลทั้งหมด **{len(target_roles)} role** ชั่วคราว\n"
            f"{E_BELL} กำลังตรวจสอบผู้กระทำ...\n"
            f"{E_SEP}"
        )
        em_start.add_field(name=f"{E_ROLE} Feature", value=f"`{feature_key}`", inline=True)
        em_start.add_field(name=f"{E_SORT} เวลา (ms)", value=f"`{_ms_adv}`", inline=True)
        em_start.add_field(name="📅 Discord timestamp", value=f"<t:{_ms_adv//1000}:F>", inline=True)
        em_start.set_footer(text=f"AdvancedMode | Guild: {guild_id}")
        em_start.timestamp = datetime.now(timezone.utc)
        await send_log(guild, em_start)

        # ── STEP 3: ระบุผู้กระทำ ──
        offender_id     = known_offender_id  # ใช้ actor ที่รู้อยู่แล้วทันที
        offender_action = feature_key.replace("anti_", "")

        # fallback: ถ้าไม่มี known_offender_id → ดึง Audit Log
        if offender_id is None:
            await asyncio.sleep(0.5)  # รอแค่ให้ Discord sync (ลดจาก 2s)
            try:
                feat = cfg.get(feature_key, {})
                window_sec = feat.get("window", 10)
                cutoff = datetime.now(timezone.utc) - timedelta(seconds=max(window_sec * 3, 60))

                ACTION_MAP = {
                    "anti_ch_delete":    discord.AuditLogAction.channel_delete,
                    "anti_ch_create":    discord.AuditLogAction.channel_create,
                    "anti_ch_update":    discord.AuditLogAction.channel_update,
                    "anti_ban":          discord.AuditLogAction.ban,
                    "anti_kick":         discord.AuditLogAction.kick,
                    "anti_role_create":  discord.AuditLogAction.role_create,
                    "anti_role_delete":  discord.AuditLogAction.role_delete,
                    "anti_role_update":  discord.AuditLogAction.role_update,
                    "anti_role_give":    discord.AuditLogAction.member_role_update,
                    "anti_webhook_create": discord.AuditLogAction.webhook_create,
                    "anti_webhook_delete": discord.AuditLogAction.webhook_delete,
                    "anti_guild_update": discord.AuditLogAction.guild_update,
                    "anti_prune":        discord.AuditLogAction.member_prune,
                }

                audit_action = ACTION_MAP.get(feature_key)
                user_counts: dict = {}

                async for entry in guild.audit_logs(limit=50, oldest_first=False):
                    if entry.created_at < cutoff:
                        break
                    if audit_action and entry.action != audit_action:
                        continue
                    uid = entry.user.id
                    if entry.user.bot:
                        continue
                    if uid == guild.owner_id:
                        continue
                    user_counts[uid] = user_counts.get(uid, 0) + 1
                    offender_action = str(entry.action).replace("AuditLogAction.", "")

                if user_counts:
                    offender_id = max(user_counts, key=user_counts.get)

            except Exception as e:
                log.error(f"[AdvLock] ดึง audit log ไม่ได้: {e}")

        # ── STEP 4: ลงโทษ ──
        if offender_id:
            try:
                offender = guild.get_member(offender_id)
                if offender is None:
                    offender = await guild.fetch_member(offender_id)
            except Exception:
                offender = None

            if offender and not is_whitelisted(offender, cfg):
                feat = cfg.get(feature_key, {})
                punishment = feat.get("punishment", "ban")
                reason = f"[AdvLock] จัดการขั้นสูง: {offender_action} เกินกำหนด"
                await apply_punishment(guild, offender, punishment, reason)
                _ms_p = int(time.time() * 1000)
                E_ARROW  = "⟫"
                E_SEP    = "─────────"
                E_CANCEL = "❌"
                E_WARN   = "⚠️"
                E_OK     = "✅"
                E_SORT   = "▷"
                em_punish = discord.Embed(title=f"{E_OK} จัดการขั้นสูง — ลงโทษแล้ว", color=0xffa502)
                em_punish.description = (
                    f"{E_ARROW} **ผู้กระทำ:** {offender.mention} `{offender}` (ID: `{offender.id}`)\n"
                    f"{E_ARROW} **Action:** `{offender_action}`\n"
                    f"{E_SEP}\n"
                    f"{E_CANCEL} **บทลงโทษ:** `{punishment.upper()}`"
                )
                em_punish.add_field(name=f"{E_WARN} เหตุผล", value=f"`{reason}`", inline=False)
                em_punish.add_field(name=f"{E_SORT} เวลา (ms)", value=f"`{_ms_p}`", inline=True)
                em_punish.add_field(name="📅 Discord timestamp", value=f"<t:{_ms_p//1000}:F>", inline=True)
                em_punish.set_footer(text=f"AdvancedMode | Guild: {guild_id}")
                em_punish.timestamp = datetime.now(timezone.utc)
                await send_log(guild, em_punish)
            else:
                _ms_nf = int(time.time() * 1000)
                E_ALERT = "🚨"
                E_SORT  = "▷"
                E_WL    = "🛡️"
                em_nf = discord.Embed(title=f"{E_ALERT} จัดการขั้นสูง — ไม่พบผู้กระทำ", color=0xffa502)
                em_nf.description = (
                    f"⟫ ไม่พบผู้กระทำที่ชัดเจนใน Audit Log\n"
                    f"{E_WL} หรือผู้กระทำอยู่ใน **Whitelist**\n"
                    f"─────────"
                )
                em_nf.add_field(name=f"{E_SORT} เวลา (ms)", value=f"`{_ms_nf}`", inline=True)
                em_nf.add_field(name="📅 Discord timestamp", value=f"<t:{_ms_nf//1000}:F>", inline=True)
                em_nf.set_footer(text=f"AdvancedMode | Guild: {guild_id}")
                em_nf.timestamp = datetime.now(timezone.utc)
                await send_log(guild, em_nf)
        else:
            _ms_nf2 = int(time.time() * 1000)
            E_ALERT = "🚨"
            E_SORT  = "▷"
            em_nf = discord.Embed(title=f"{E_ALERT} จัดการขั้นสูง — ไม่พบผู้กระทำ", color=0xffa502)
            em_nf.description = (
                f"⟫ ไม่พบผู้กระทำที่ตรงกับ action นี้ใน Audit Log\n"
                f"─────────"
            )
            em_nf.add_field(name=f"{E_SORT} เวลา (ms)", value=f"`{_ms_nf2}`", inline=True)
            em_nf.add_field(name="📅 Discord timestamp", value=f"<t:{_ms_nf2//1000}:F>", inline=True)
            em_nf.set_footer(text=f"AdvancedMode | Guild: {guild_id}")
            em_nf.timestamp = datetime.now(timezone.utc)
            await send_log(guild, em_nf)

    except Exception as e:
        log.error(f"[AdvLock] error: {e}")

    finally:
        # ── STEP 5: คืน permissions ทุก role เสมอ ──
        await asyncio.sleep(0.2)  # ลดจาก 1s
        restore_tasks = []
        restore_done  = []
        for role in guild.roles:
            orig = saved_perms.get(role.id)
            if orig is not None:
                restore_tasks.append(role.edit(permissions=orig, reason="[AdvLock] คืนสิทธิ์หลังตรวจสอบ"))
                restore_done.append(role.name)

        if restore_tasks:
            results = await asyncio.gather(*restore_tasks, return_exceptions=True)
            for i, res in enumerate(results):
                if isinstance(res, Exception):
                    log.warning(f"[AdvLock] คืน role {restore_done[i]} ไม่ได้: {res}")

        # ล้าง state
        bot.adv_lock_state.pop(guild_id, None)
        bot.adv_lock_active.discard(guild_id)
        cfg = get_cfg(guild_id)
        cfg["_adv_lock_state"] = {}
        await save_guild_data(guild_id)

        _ms_done = int(time.time() * 1000)
        E_OK   = "✅"
        E_ROLE = "🏷️"
        E_SEP  = "─────────"
        E_SORT = "▷"
        E_ARROW= "⟫"
        em_done = discord.Embed(title=f"{E_OK} จัดการขั้นสูง — เสร็จสิ้น", color=0x00c896)
        em_done.description = (
            f"{E_ARROW} คืนสิทธิ์ **{len(saved_perms)} role** กลับเหมือนเดิมแล้ว\n"
            f"{E_SEP}"
        )
        em_done.add_field(name=f"{E_ROLE} Role ที่คืน", value=f"`{len(saved_perms)}` role", inline=True)
        em_done.add_field(name=f"{E_SORT} เวลา (ms)", value=f"`{_ms_done}`", inline=True)
        em_done.add_field(name="📅 Discord timestamp", value=f"<t:{_ms_done//1000}:F>", inline=True)
        em_done.set_footer(text=f"AdvancedMode | Guild: {guild_id}")
        em_done.timestamp = datetime.now(timezone.utc)
        await send_log(guild, em_done)
        log.info(f"[AdvLock] {guild.name}: เสร็จสิ้น คืน {len(saved_perms)} role แล้ว")
async def api_advanced_manage(req):
    """
    POST /api/advanced-manage
    body: { "feature_key": "anti_ch_delete", "enabled": true/false }
    → เปิด/ปิดโหมดจัดการขั้นสูงสำหรับ feature นั้น
    เมื่อเปิด: check_feature จะเรียก do_advanced_lockdown แทนการลงโทษปกติ
    """
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    guild = bot.get_guild(d["guild_id"])
    if not guild: return jres({"error": "guild not found"}, 404)
    try:
        body = await req.json()
        feature_key = body.get("feature_key", "")
        enabled     = bool(body.get("enabled", True))
        cfg = get_cfg(guild.id)
        # บันทึกโหมดใน config
        adv_modes = cfg.setdefault("advanced_mode", {})
        adv_modes[feature_key] = enabled
        await save_guild_data(d["guild_id"])
        return jres({"success": True, "feature_key": feature_key, "enabled": enabled})
    except Exception as e:
        return jres({"error": str(e)}, 400)


async def api_lockdown(req):
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    guild = bot.get_guild(d["guild_id"])
    if not guild: return jres({"error": "guild not found"}, 404)
    try:
        body = await req.json()
        enable = bool(body.get("enable", True))
        # [Audit Session 4] แก้ race condition: await do_lockdown ก่อน แล้วค่อย save
        # (เดิม create_task แล้ว save ทันที อาจ double-trigger ถ้า Dashboard กด save ซ้ำ)
        await do_lockdown(guild, enable)
        cfg = get_cfg(guild.id)
        cfg["server_lockdown"]["enabled"] = enable
        await save_guild_data(guild.id)
        return jres({"success": True, "lockdown": enable})
    except Exception as e:
        return jres({"error": str(e)}, 400)

async def api_role_manager_get(req):
    """GET /api/role-manager — คืน role_manager config ของ guild"""
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    cfg = get_cfg(d["guild_id"])
    return jres(cfg.get("role_manager", {"member_roles": [], "dangerous_roles": [], "exempt_roles": []}))

async def api_role_manager_post(req):
    """POST /api/role-manager — บันทึก role_manager config"""
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    try:
        body = await req.json()
        cfg  = get_cfg(d["guild_id"])
        rm   = cfg.setdefault("role_manager", {"member_roles": [], "dangerous_roles": [], "exempt_roles": []})
        for key in ("member_roles", "dangerous_roles", "exempt_roles"):
            if key in body:
                rm[key] = [str(x) for x in body[key]]
        await save_guild_data(d["guild_id"])
        return jres({"success": True, "role_manager": rm})
    except Exception as e:
        return jres({"error": str(e)}, 400)

async def api_member_detail(req):
    """Return member profile + per-protection exemptions stored in config."""
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    guild = bot.get_guild(d["guild_id"])
    if not guild: return jres({"error": "guild not found"}, 404)
    member_id = req.rel_url.query.get("member_id", "")
    if not member_id: return jres({"error": "member_id required"}, 400)
    try:
        member = guild.get_member(int(member_id))
        if not member: return jres({"error": "member not found"}, 404)
        cfg = get_cfg(guild.id)
        exemptions = cfg.get("member_exemptions", {}).get(member_id, {})
        roles = [{"id": str(r.id), "name": r.name, "color": str(r.color)} for r in member.roles if r.name != "@everyone"]
        return jres({
            "id":           str(member.id),
            "name":         member.name,
            "display_name": member.display_name,
            "global_name":  member.global_name or member.name,
            "avatar":       str(member.display_avatar.url),
            "joined_at":    member.joined_at.isoformat() if member.joined_at else None,
            "created_at":   member.created_at.isoformat(),
            "is_owner":     member.id == guild.owner_id,
            "roles":        roles,
            "exemptions":   exemptions,
        })
    except Exception as e:
        return jres({"error": str(e)}, 500)

async def api_save_member_exemptions(req):
    """Save per-member exemption settings."""
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    try:
        body = await req.json()
        member_id = str(body.get("member_id", ""))
        exemptions = body.get("exemptions", {})
        cfg = get_cfg(d["guild_id"])
        if "member_exemptions" not in cfg:
            cfg["member_exemptions"] = {}
        cfg["member_exemptions"][member_id] = exemptions
        await save_guild_data(d["guild_id"])
        return jres({"success": True})
    except Exception as e:
        return jres({"error": str(e)}, 400)

async def api_role_channels(req):
    """Return all channels with visibility/send-message permission for a given role."""
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    guild = bot.get_guild(d["guild_id"])
    if not guild: return jres({"error": "guild not found"}, 404)
    role_id = req.rel_url.query.get("role_id", "")
    if not role_id: return jres({"error": "role_id required"}, 400)
    try:
        role = guild.get_role(int(role_id))
        if not role: return jres({"error": "role not found"}, 404)
        result = []
        for ch in sorted(guild.channels, key=lambda c: (str(type(c).__name__), c.position)):
            if not isinstance(ch, (discord.TextChannel, discord.VoiceChannel, discord.ForumChannel)):
                continue
            perms = ch.permissions_for(role)
            can_view = perms.view_channel
            can_send = perms.send_messages if isinstance(ch, discord.TextChannel) else perms.connect
            category = ch.category.name if ch.category else "—"
            result.append({
                "id":       str(ch.id),
                "name":     ch.name,
                "type":     type(ch).__name__,
                "category": category,
                "can_view": can_view,
                "can_send": can_send,
            })
        return jres(result)
    except Exception as e:
        return jres({"error": str(e)}, 500)

async def api_suspicious_alerts(req):
    """Return suspicious behavior alerts for the guild."""
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    guild = bot.get_guild(d["guild_id"])
    if not guild: return jres({"error": "guild not found"}, 404)
    alerts = list(reversed(bot.suspicious_alerts[d["guild_id"]]))
    # Enrich with member info
    result = []
    for a in alerts:
        member = guild.get_member(a["user_id"])
        result.append({
            **a,
            "user_id":      str(a["user_id"]),
            "ts":           a["ts"],
            "member_name":  member.display_name if member else f"Unknown ({a['user_id']})",
            "member_avatar": str(member.display_avatar.url) if member else "",
        })
    return jres(result)

async def api_mark_alert_read(req):
    """Mark a suspicious alert as read."""
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    try:
        body = await req.json()
        alert_id = body.get("id", "")
        for a in bot.suspicious_alerts[d["guild_id"]]:
            if a["id"] == alert_id:
                a["read"] = True
                break
        return jres({"success": True})
    except Exception as e:
        return jres({"error": str(e)}, 400)

async def api_member_actions(req):
    """Return action history for a specific member."""
    t = req.rel_url.query.get("token", "")
    d = verify_token(t)
    if not d: return jres({"error": "unauthorized"}, 401)
    member_id = req.rel_url.query.get("member_id", "")
    if not member_id: return jres({"error": "member_id required"}, 400)
    actions = list(reversed(bot.member_actions[d["guild_id"]].get(int(member_id), [])))
    return jres(actions[:100])  # last 100 actions

# ══════════════════════════════════════════════════════════════════
#  DASHBOARD HTML — Single-Page Application (SPA)
#  HTML ทั้งหมดถูก embed อยู่ใน string นี้ เสิร์ฟโดย page_index()
#  ใช้ Chart.js สำหรับ donut chart (สัดส่วน protection) + bar chart (สถิติ server)
#  ใช้ Lucide icons และ font Kanit + JetBrains Mono
#
#  หน้าหลักใน Dashboard:
#    home       — overview: สถิติ server, chart protection, สถานะ raid/lockdown
#    antinuke   — ตั้งค่า Anti-Nuke ทุก feature (ban/kick/channel/role/webhook/...)
#    antiraid   — ตั้งค่า Anti-Raid (join flood, account age, no avatar, lockdown)
#    antispam   — ตั้งค่า Anti-Spam (text, mention, link, attachment, emoji)
#    general    — ตั้งค่าทั่วไป (AutoMod, voice abuse, welcome, verification)
#    settings   — log channels, role manager, advanced lockdown
#    whitelist  — จัดการ whitelist user/role
#    logs       — audit log ย้อนหลัง
#    members    — จัดการสมาชิก + per-member exemption
#    alerts     — Suspicious Behavior Tracker alerts
#
#  page_index() แทนที่ API_BASE URL ใน JS ก่อนเสิร์ฟ (inject config จาก ENV)
#  Floating Save Button (fab-save) ปรากฏบนทุกหน้าที่มีการตั้งค่า
# ══════════════════════════════════════════════════════════════════
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="th">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0,maximum-scale=1.0,user-scalable=no"/>
<title>Security Bot Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Kanit:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet"/>
<script src="https://cdnjs.cloudflare.com/ajax/libs/lucide/0.383.0/umd/lucide.min.js"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<style>
:root{
  --bg:#07090f;--surface:#0d1117;--surface2:#111827;--surface3:#1a2234;
  --border:#1e2d45;--border2:#263552;--text:#c9d8f0;--muted:#3d5478;--muted2:#5a7ba0;
  --primary:#3b6ef8;--primary-light:#5585ff;--primary-glow:rgba(59,110,248,.2);
  --accent:#00d4ff;--success:#00c896;--success-dim:rgba(0,200,150,.12);
  --danger:#ff4757;--danger-dim:rgba(255,71,87,.12);
  --warn:#ffa502;--warn-dim:rgba(255,165,2,.12);
  --purple:#a855f7;--purple-dim:rgba(168,85,247,.12);
  --sidebar:240px;--nav-h:60px;--r:14px;--r-sm:9px;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
html,body{height:100%;overflow-x:hidden;}
body{font-family:'Kanit',sans-serif;background:var(--bg);color:var(--text);min-height:100%;overflow-x:hidden;font-size:14px;line-height:1.55;}
::-webkit-scrollbar{width:4px;height:4px;}
::-webkit-scrollbar-track{background:transparent;}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:4px;}
.hidden{display:none!important;}
.mono{font-family:'JetBrains Mono',monospace;}

/* ═══ THREAT DASHBOARD ═══ */
.threat-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px;}
.threat-gauge{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:16px 12px;display:flex;flex-direction:column;align-items:center;gap:8px;cursor:default;}
.gauge-ring{position:relative;width:80px;height:80px;}
.gauge-ring svg{width:80px;height:80px;transform:rotate(-90deg);}
.gauge-bg{fill:none;stroke:var(--border2);stroke-width:7;}
.gauge-fill{fill:none;stroke-width:7;stroke-linecap:round;transition:stroke-dashoffset .8s cubic-bezier(.4,0,.2,1),stroke .4s;}
.gauge-val{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;font-size:16px;font-weight:800;color:var(--text);}
.gauge-label{font-size:11px;font-weight:700;color:var(--muted2);text-align:center;letter-spacing:.3px;}
.gauge-sub{font-size:10px;color:var(--muted);text-align:center;}
.threat-level-bar{display:flex;align-items:center;gap:10px;background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:14px 16px;margin-bottom:12px;}
.tlb-label{font-size:11px;font-weight:700;color:var(--muted2);min-width:64px;letter-spacing:.4px;}
.tlb-track{flex:1;height:6px;background:var(--border2);border-radius:4px;overflow:hidden;}
.tlb-fill{height:100%;border-radius:4px;transition:width .7s cubic-bezier(.4,0,.2,1);}
.tlb-val{font-size:12px;font-weight:700;min-width:30px;text-align:right;}
.threat-live-dot{width:7px;height:7px;border-radius:50%;display:inline-block;margin-right:5px;animation:pulse-dot 1.6s ease-in-out infinite;}
@keyframes pulse-dot{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.5;transform:scale(.7)}}
.threat-status-ok{color:var(--success);}
.threat-status-warn{color:var(--warn);}
.threat-status-danger{color:var(--danger);}

/* ═══ ACTION TIMELINE ═══ */
.timeline-wrap{display:flex;flex-direction:column;gap:0;position:relative;padding-left:28px;}
.timeline-wrap::before{content:'';position:absolute;left:10px;top:6px;bottom:6px;width:1.5px;background:linear-gradient(to bottom,var(--primary-light),var(--border));opacity:.3;border-radius:2px;}
.tl-item{position:relative;padding:10px 0 10px 14px;animation:fadeUp .3s ease both;}
.tl-dot{position:absolute;left:-22px;top:14px;width:10px;height:10px;border-radius:50%;border:2px solid var(--bg);box-shadow:0 0 0 1.5px currentColor;}
.tl-dot.c-danger{color:var(--danger);background:var(--danger);}
.tl-dot.c-warn{color:var(--warn);background:var(--warn);}
.tl-dot.c-success{color:var(--success);background:var(--success);}
.tl-dot.c-info{color:var(--primary-light);background:var(--primary-light);}
.tl-dot.c-gray{color:var(--muted2);background:var(--muted2);}
.tl-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r-sm);padding:10px 12px;}
.tl-card:hover{border-color:var(--border2);background:var(--surface2);}
.tl-top{display:flex;align-items:center;gap:8px;margin-bottom:3px;}
.tl-badge{font-size:10px;font-weight:700;padding:2px 7px;border-radius:20px;text-transform:uppercase;letter-spacing:.4px;}
.tl-time{font-size:10px;color:var(--muted);margin-left:auto;}
.tl-desc{font-size:12px;color:var(--text);line-height:1.45;}
.tl-meta{font-size:11px;color:var(--muted);margin-top:2px;}
.tl-filter-row{display:flex;gap:6px;margin-bottom:12px;flex-wrap:wrap;}
.tl-filter-btn{font-size:11px;font-weight:600;padding:4px 12px;border-radius:20px;border:1px solid var(--border2);background:transparent;color:var(--muted2);cursor:pointer;transition:all .15s;}
.tl-filter-btn.active{background:var(--primary-glow);border-color:var(--primary-light);color:var(--primary-light);}
.tl-empty{text-align:center;padding:40px 0;color:var(--muted);font-size:13px;}

/* ═══ WEEKLY REPORT ═══ */
.report-hero{background:linear-gradient(135deg,rgba(59,110,248,.15),rgba(168,85,247,.1));border:1px solid rgba(59,110,248,.2);border-radius:var(--r);padding:20px;margin-bottom:14px;display:flex;align-items:center;gap:16px;}
.report-hero-ic{width:52px;height:52px;border-radius:14px;background:rgba(59,110,248,.18);display:flex;align-items:center;justify-content:center;flex-shrink:0;}
.report-hero-text h2{font-size:16px;font-weight:800;color:var(--text);margin-bottom:3px;}
.report-hero-text p{font-size:12px;color:var(--muted2);}
.report-kpi-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-bottom:14px;}
.report-kpi{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:14px;}
.report-kpi-num{font-size:28px;font-weight:800;line-height:1;margin-bottom:4px;}
.report-kpi-label{font-size:11px;color:var(--muted2);font-weight:600;}
.report-kpi-trend{font-size:10px;margin-top:4px;}
.trend-up{color:var(--danger);}
.trend-down{color:var(--success);}
.trend-same{color:var(--muted);}
.report-bar-row{display:flex;align-items:center;gap:10px;padding:8px 0;border-bottom:1px solid var(--border);}
.report-bar-row:last-child{border-bottom:none;}
.report-bar-label{font-size:12px;color:var(--text);min-width:100px;}
.report-bar-track{flex:1;height:5px;background:var(--border2);border-radius:3px;overflow:hidden;}
.report-bar-fill{height:100%;border-radius:3px;transition:width .8s cubic-bezier(.4,0,.2,1);}
.report-bar-count{font-size:12px;font-weight:700;min-width:28px;text-align:right;}
.report-week-nav{display:flex;align-items:center;gap:8px;margin-bottom:14px;}
.report-week-nav button{background:var(--surface2);border:1px solid var(--border2);border-radius:8px;color:var(--muted2);padding:5px 10px;cursor:pointer;font-size:13px;transition:color .15s;}
.report-week-nav button:hover{color:var(--text);}
.report-week-label{flex:1;text-align:center;font-size:13px;font-weight:700;color:var(--text);}

/* ANIMATIONS */
@keyframes fadeUp{from{opacity:0;transform:translateY(18px)}to{opacity:1;transform:translateY(0)}}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes glow{0%,100%{box-shadow:0 0 20px rgba(59,110,248,.3)}50%{box-shadow:0 0 40px rgba(59,110,248,.6)}}
@keyframes toastIn{from{opacity:0;transform:translateX(110%)}to{opacity:1;transform:translateX(0)}}
@keyframes toastOut{from{opacity:1}to{opacity:0;transform:translateX(110%)}}
@keyframes shimmer{0%{background-position:-600px 0}100%{background-position:600px 0}}
/* BUTTON SVG ANIMATIONS */
@keyframes btn-bounce{0%,100%{transform:translateY(0)}40%{transform:translateY(-4px)}70%{transform:translateY(-2px)}}
@keyframes btn-shake{0%,100%{transform:rotate(0)}20%{transform:rotate(-12deg)}40%{transform:rotate(10deg)}60%{transform:rotate(-8deg)}80%{transform:rotate(6deg)}}
@keyframes btn-pulse-ring{0%{transform:scale(1);opacity:1}100%{transform:scale(1.7);opacity:0}}
@keyframes btn-ping{0%,100%{transform:scale(1)}50%{transform:scale(1.18)}}
@keyframes btn-spin-once{0%{transform:rotate(0deg)}100%{transform:rotate(360deg)}}
@keyframes btn-ripple{0%{transform:scale(0);opacity:.5}100%{transform:scale(2.8);opacity:0}}
@keyframes btn-wobble{0%,100%{transform:scaleX(1)}30%{transform:scaleX(1.12) scaleY(.9)}60%{transform:scaleX(.95) scaleY(1.05)}}
@keyframes btn-draw{0%{stroke-dashoffset:60}100%{stroke-dashoffset:0}}

/* LOGIN */
#login-view{position:fixed;inset:0;z-index:1000;display:flex;align-items:center;justify-content:center;
  background:radial-gradient(ellipse 80% 50% at 30% 20%,rgba(59,110,248,.12),transparent),
  radial-gradient(ellipse 50% 60% at 80% 80%,rgba(0,212,255,.07),transparent),var(--bg);
  background-size:auto,auto,auto;
}
.login-card{width:100%;max-width:400px;margin:20px;background:var(--surface);border:1px solid var(--border);
  border-radius:20px;padding:40px 36px;display:flex;flex-direction:column;gap:22px;
  animation:fadeUp .6s cubic-bezier(.16,1,.3,1) both;box-shadow:0 40px 80px rgba(0,0,0,.65),0 0 0 1px rgba(59,110,248,.1),inset 0 1px 0 rgba(255,255,255,.04);}
.login-logo{display:flex;flex-direction:column;align-items:center;gap:14px;text-align:center;}
.logo-ring{width:72px;height:72px;background:linear-gradient(135deg,var(--primary) 0%,var(--accent) 100%);
  border-radius:20px;display:flex;align-items:center;justify-content:center;animation:glow 3s ease-in-out infinite;box-shadow:0 8px 24px rgba(59,110,248,.45);}
.login-title{font-size:26px;font-weight:800;color:#fff;letter-spacing:-.5px;}
.login-sub{font-size:13px;color:var(--muted2);}
.fl{display:flex;flex-direction:column;gap:8px;}
.fl label{font-size:11px;font-weight:600;color:var(--muted2);text-transform:uppercase;letter-spacing:.7px;}
.fi{background:var(--surface2);border:1.5px solid var(--border2);border-radius:var(--r-sm);padding:13px 14px;
  color:var(--text);font-size:14px;font-family:'Kanit',sans-serif;outline:none;width:100%;min-height:48px;transition:border-color .2s,box-shadow .2s;}
.fi:focus{border-color:var(--primary-light);box-shadow:0 0 0 3px var(--primary-glow);}
.fi::placeholder{color:var(--muted);}
.btn-login{background:linear-gradient(135deg,var(--primary),var(--primary-light));color:#fff;border:none;
  border-radius:var(--r-sm);padding:14px;font-size:14px;font-weight:700;font-family:'Kanit',sans-serif;
  cursor:pointer;width:100%;min-height:48px;box-shadow:0 4px 20px rgba(59,110,248,.4);transition:transform .15s,box-shadow .15s;
  display:flex;align-items:center;justify-content:center;gap:8px;letter-spacing:.3px;}
.btn-login:hover{transform:translateY(-1px);box-shadow:0 8px 28px rgba(59,110,248,.6);}
.login-hint{text-align:center;font-size:12px;color:var(--muted);}
.login-hint code{background:var(--surface2);padding:2px 7px;border-radius:5px;color:var(--accent);font-family:'JetBrains Mono',monospace;font-size:11px;}
.login-err{display:none;background:var(--danger-dim);border:1px solid rgba(255,71,87,.3);color:#ffa0aa;border-radius:var(--r-sm);padding:10px 14px;font-size:13px;}
.login-err.show{display:block;}

/* APP */
#app-view{display:none;min-height:100vh;}
#app-view.active{display:flex;}

/* SIDEBAR */
#sidebar{width:var(--sidebar);min-height:100vh;background:linear-gradient(180deg,#0c1220 0%,#070c18 100%);
  border-right:1px solid var(--border);position:fixed;left:0;top:0;bottom:0;z-index:100;display:flex;flex-direction:column;overflow:hidden;}
.sb-head{padding:22px 16px 16px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:12px;}
.sb-icon{width:40px;height:40px;border-radius:12px;flex-shrink:0;background:linear-gradient(135deg,var(--primary),var(--accent));
  display:flex;align-items:center;justify-content:center;box-shadow:0 4px 14px rgba(59,110,248,.4);}
.sb-title{font-size:14px;font-weight:700;color:#fff;letter-spacing:.3px;}
.sb-sub{font-size:10px;color:var(--muted);margin-top:1px;letter-spacing:.4px;}
.sb-server{margin:10px 10px 4px;padding:11px 12px;background:var(--surface2);border:1px solid var(--border);border-radius:10px;display:flex;align-items:center;gap:9px;transition:border-color .15s;}
.sb-server:hover{border-color:var(--border2);}
.sb-sicon{width:34px;height:34px;border-radius:8px;flex-shrink:0;background:var(--primary-glow);overflow:hidden;display:flex;align-items:center;justify-content:center;color:var(--primary-light);}
.sb-sicon img{width:100%;height:100%;object-fit:cover;border-radius:8px;}
.sb-sname{font-size:12px;font-weight:600;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.sb-sid{font-size:10px;color:var(--muted);font-family:'JetBrains Mono',monospace;}
.sb-nav{flex:1;overflow-y:auto;padding:6px 8px;display:flex;flex-direction:column;gap:1px;}
.sb-nav::-webkit-scrollbar{width:0;}
.sb-section{font-size:9.5px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:1.1px;padding:14px 8px 3px;display:flex;align-items:center;gap:5px;}
.nav-item{display:flex;align-items:center;gap:9px;padding:8px 10px;border-radius:8px;cursor:pointer;color:var(--muted2);
  font-size:12.5px;font-weight:400;transition:all .18s;border:1px solid transparent;user-select:none;position:relative;overflow:hidden;}
.nav-item:hover{background:var(--surface2);color:var(--text);transform:translateX(3px);}
.nav-item:active{transform:translateX(1px) scale(.98);}
.nav-item.active{background:linear-gradient(90deg,rgba(59,110,248,.18),rgba(59,110,248,.05));color:var(--primary-light);border-color:rgba(91,133,255,.2);font-weight:500;}
.nav-item.active .nav-ic svg{stroke:var(--primary-light);}
/* Nav icon SVG animation on hover */
.nav-item:hover .nav-ic svg{animation:nav-icon-pop .3s cubic-bezier(.34,1.56,.64,1) both;}
.nav-item.active .nav-ic svg{animation:nav-icon-glow 2.5s ease-in-out infinite;}
@keyframes nav-icon-pop{0%{transform:scale(1) rotate(0)}40%{transform:scale(1.3) rotate(-8deg)}70%{transform:scale(1.15) rotate(4deg)}100%{transform:scale(1.1) rotate(0)}}
@keyframes nav-icon-glow{0%,100%{opacity:1;filter:drop-shadow(0 0 0px currentColor)}50%{opacity:.85;filter:drop-shadow(0 0 4px currentColor)}}
/* Nav ripple */
.nav-item::after{content:'';position:absolute;inset:0;background:rgba(91,133,255,.08);transform:scaleX(0);transform-origin:left;border-radius:8px;transition:transform .25s ease;pointer-events:none;}
.nav-item:hover::after{transform:scaleX(1);}
.nav-dot{width:6px;height:6px;border-radius:50%;background:var(--success);flex-shrink:0;display:none;box-shadow:0 0 6px var(--success);animation:nav-dot-pulse 2s ease-in-out infinite;}
@keyframes nav-dot-pulse{0%,100%{box-shadow:0 0 4px var(--success),0 0 0 0 rgba(0,200,150,.5)}50%{box-shadow:0 0 8px var(--success),0 0 0 4px rgba(0,200,150,0)}}
.nav-item.active .nav-dot{display:block;}
.nav-ic{width:20px;flex-shrink:0;display:flex;align-items:center;justify-content:center;}
.nav-ic svg{width:14px;height:14px;stroke-width:1.8;transition:stroke .14s;}
.sb-foot{padding:10px;border-top:1px solid var(--border);}
.sb-logout{display:flex;align-items:center;gap:8px;padding:9px 10px;border-radius:8px;cursor:pointer;color:var(--muted2);font-size:12.5px;transition:all .2s;overflow:hidden;position:relative;}
.sb-logout:hover{background:var(--danger-dim);color:var(--danger);transform:translateX(3px);}
.sb-logout:hover svg{animation:btn-shake .4s ease both;}

/* MAIN */
#main{margin-left:var(--sidebar);flex:1;min-height:100vh;display:flex;flex-direction:column;}
.main-head{padding:22px 28px 0;display:flex;align-items:center;justify-content:space-between;gap:16px;}
.page-title{font-size:20px;font-weight:800;color:#fff;letter-spacing:-.3px;}
.page-sub{font-size:12px;color:var(--muted);margin-top:3px;}
.main-body{padding:20px 24px 56px;}
.page{display:none;}
.page.active{display:block;animation:fadeUp .35s cubic-bezier(.16,1,.3,1) both;}

/* CARD */
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:20px;margin-bottom:14px;transition:border-color .15s;}
.card-title{font-size:10.5px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.9px;margin-bottom:16px;display:flex;align-items:center;gap:7px;}

/* STATS */
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px;}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:18px 16px 14px;position:relative;overflow:hidden;animation:fadeUp .4s cubic-bezier(.16,1,.3,1) both;transition:border-color .15s,transform .2s,box-shadow .2s;}
.stat-card:hover{border-color:var(--border2);transform:translateY(-3px);box-shadow:0 8px 28px rgba(0,0,0,.3);}
/* stat icon floats + glows on hover */
.stat-card:hover .stat-ic svg{animation:stat-float .5s ease-in-out infinite alternate;}
@keyframes stat-float{0%{transform:translateY(0) scale(1)}100%{transform:translateY(-3px) scale(1.1)}}
.stat-ic{position:absolute;top:12px;right:12px;font-size:22px;opacity:1;display:flex;align-items:center;justify-content:center;}
.stat-num{font-size:30px;font-weight:800;color:#fff;letter-spacing:-1.5px;line-height:1;margin-top:6px;}
.stat-label{font-size:11px;color:var(--muted2);margin-top:5px;letter-spacing:.3px;}

/* BANNER */
#server-banner{height:140px;border-radius:var(--r);margin-bottom:14px;position:relative;overflow:hidden;border:1px solid var(--border);background:linear-gradient(135deg,#0a1628,#07121f);}
/* [Session 5] ซ่อน gradient เมื่อมีรูป banner จริง */
#server-banner.has-banner .banner-bg{display:none;}
#banner-img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover;object-position:center;filter:brightness(.55);}
#banner-overlay{position:absolute;inset:0;background:linear-gradient(to top,rgba(0,0,0,.75) 0%,transparent 60%);}
.banner-bg{position:absolute;inset:0;background:linear-gradient(135deg,rgba(59,110,248,.3),rgba(0,212,255,.12));}
.banner-content{position:relative;z-index:1;padding:18px;display:flex;align-items:flex-end;height:100%;}
.banner-icon{width:60px;height:60px;border-radius:14px;border:2px solid rgba(255,255,255,.15);background:var(--primary);display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:800;color:#fff;overflow:hidden;flex-shrink:0;}
.banner-icon img{width:100%;height:100%;object-fit:cover;}
.banner-info{margin-left:14px;}
.banner-name{font-size:20px;font-weight:800;color:#fff;letter-spacing:-.4px;text-shadow:0 2px 8px rgba(0,0,0,.4);}
.banner-members{font-size:12px;color:rgba(255,255,255,.6);margin-top:2px;}

/* FEATURE GRID — 1 feature = 1 card */
.feature-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:14px;margin-bottom:14px;}
.feat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);overflow:hidden;transition:border-color .15s,box-shadow .15s,transform .15s;animation:fadeUp .4s cubic-bezier(.16,1,.3,1) both;}
.feat-card:hover{border-color:var(--border2);transform:translateY(-1px);box-shadow:0 4px 16px rgba(0,0,0,.2);}
.feat-card.enabled{border-color:rgba(59,110,248,.45);box-shadow:0 0 0 1px rgba(59,110,248,.15),0 4px 20px rgba(59,110,248,.08);}
.feat-header{display:flex;align-items:center;gap:12px;padding:14px 16px;border-bottom:1px solid var(--border);background:linear-gradient(90deg,var(--surface2),var(--surface));}
.feat-emoji{font-size:20px;width:28px;height:28px;display:flex;align-items:center;justify-content:center;flex-shrink:0;color:var(--muted2);}
.feat-emoji svg{width:16px;height:16px;stroke-width:1.8;}
.feat-label{flex:1;}
.feat-name{font-size:14px;font-weight:700;color:#fff;}
.feat-desc{font-size:11px;color:var(--muted);margin-top:1px;}
.feat-body{padding:14px 16px;display:flex;flex-direction:column;gap:11px;}

/* TOGGLE */
.tog{position:relative;display:inline-block;width:48px;height:26px;flex-shrink:0;}
.tog input{opacity:0;width:0;height:0;}
.tog-sl{position:absolute;cursor:pointer;inset:0;background:var(--border2);border-radius:26px;transition:background .25s;}
.tog-sl::before{content:'';position:absolute;width:20px;height:20px;left:3px;top:3px;background:#fff;border-radius:50%;transition:transform .25s cubic-bezier(.34,1.56,.64,1),box-shadow .25s;box-shadow:0 1px 4px rgba(0,0,0,.4);}
.tog input:checked+.tog-sl{background:var(--success);}
.tog input:checked+.tog-sl::before{transform:translateX(22px);box-shadow:0 0 8px rgba(0,200,150,.5);}
/* Whole toggle bounces when label row is hovered */
.trow:hover .tog-sl::before,.adv-toggle-row:hover .tog-sl::before{box-shadow:0 1px 4px rgba(0,0,0,.4),0 0 0 3px rgba(91,133,255,.15);}

/* FIELD */
.sub-field{display:flex;flex-direction:column;gap:5px;}
.sub-label{font-size:10px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.6px;}
.sub-row{display:flex;gap:8px;align-items:center;}
.sub-input{background:var(--surface2);border:1.5px solid var(--border2);border-radius:var(--r-sm);padding:7px 10px;
  color:var(--text);font-size:13px;font-family:'Kanit',sans-serif;outline:none;flex:1;min-height:36px;transition:border-color .2s;}
.sub-input:focus{border-color:var(--primary-light);}
.sub-unit{font-size:11px;color:var(--muted);white-space:nowrap;}
.sub-select{background:var(--surface2);border:1.5px solid var(--border2);border-radius:var(--r-sm);padding:6px 8px;color:var(--text);font-size:11px;cursor:pointer;outline:none;}
.sub-select:focus{border-color:var(--primary-light);}

/* PUNISHMENT SELECTOR */
.punish-wrap{display:grid;grid-template-columns:repeat(3,1fr);gap:5px;}
.punish-btn{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:2px;padding:7px 3px;
  border-radius:7px;border:1.5px solid var(--border);background:var(--surface2);cursor:pointer;
  transition:all .18s;color:var(--muted2);font-size:10px;font-weight:600;font-family:'Kanit',sans-serif;position:relative;overflow:hidden;}
.punish-btn:hover{border-color:var(--border2);color:var(--text);transform:scale(1.06);}
.punish-btn:active{transform:scale(.95);}
/* punish icon bounces on hover */
.punish-btn:hover .punish-ic{animation:btn-bounce .35s ease both;}
.punish-btn.sel{border-color:var(--primary-light);background:var(--primary-glow);color:var(--primary-light);}
.punish-btn.sel.p-ban{border-color:var(--danger);background:var(--danger-dim);color:var(--danger);}
.punish-btn.sel.p-kick{border-color:var(--warn);background:var(--warn-dim);color:var(--warn);}
.punish-btn.sel.p-timeout{border-color:var(--accent);background:rgba(0,212,255,.1);color:var(--accent);}
.punish-btn.sel.p-quarantine{border-color:var(--purple);background:var(--purple-dim);color:var(--purple);}
.punish-btn.sel.p-log{border-color:var(--muted2);background:rgba(90,123,160,.1);color:var(--muted2);}
.punish-ic{font-size:14px;line-height:1;display:flex;align-items:center;justify-content:center;width:18px;height:18px;transition:transform .18s;}

.adv-toggle-row{display:flex;align-items:center;gap:14px;padding:13px 16px;
  background:linear-gradient(90deg,rgba(168,85,247,.08),rgba(255,71,87,.05));
  border-top:1px solid rgba(168,85,247,.2);border-radius:0 0 var(--r) var(--r);
  transition:background .2s;}
.adv-toggle-row:has(input:checked){background:linear-gradient(90deg,rgba(168,85,247,.18),rgba(255,71,87,.10));border-top-color:rgba(168,85,247,.4);}
.adv-toggle-ic{width:26px;height:26px;flex-shrink:0;display:flex;align-items:center;justify-content:center;
  background:rgba(168,85,247,.15);border-radius:7px;color:#c084fc;}
.adv-toggle-info{flex:1;}
.adv-toggle-label{font-size:13px;font-weight:700;color:#c084fc;}
.adv-toggle-desc{font-size:11px;color:var(--muted);margin-top:2px;}

/* BUTTONS */
.btn{display:inline-flex;align-items:center;gap:6px;padding:9px 16px;border-radius:var(--r-sm);border:1px solid var(--border2);
  background:var(--surface2);color:var(--text);font-size:13px;font-weight:600;font-family:'Kanit',sans-serif;cursor:pointer;transition:all .2s;white-space:nowrap;min-height:40px;
  position:relative;overflow:hidden;}
.btn:hover{background:var(--surface3);border-color:var(--border2);transform:translateY(-1px);}
.btn:active{transform:translateY(0) scale(.97);}

/* Ripple layer */
.btn-ripple{position:absolute;border-radius:50%;pointer-events:none;transform:scale(0);animation:btn-ripple .5s ease-out forwards;}

/* Primary — SVG bounces on hover */
.btn-primary{background:var(--primary);border-color:var(--primary);color:#fff;box-shadow:0 2px 12px rgba(59,110,248,.3);}
.btn-primary:hover{background:var(--primary-light);box-shadow:0 6px 20px rgba(59,110,248,.5);}
.btn-primary:hover svg{animation:btn-bounce .45s ease both;}
.btn-ripple-primary{background:rgba(255,255,255,.35);}

/* Success — SVG pings (scale pulse) on hover */
.btn-success{background:var(--success-dim);border-color:rgba(0,200,150,.3);color:var(--success);}
.btn-success:hover{background:rgba(0,200,150,.2);border-color:rgba(0,200,150,.5);}
.btn-success:hover svg{animation:btn-ping .4s ease both;}
.btn-ripple-success{background:rgba(0,200,150,.3);}

/* Danger — SVG shakes on hover */
.btn-danger{background:var(--danger-dim);border-color:rgba(255,71,87,.3);color:var(--danger);}
.btn-danger:hover{background:rgba(255,71,87,.2);border-color:rgba(255,71,87,.5);}
.btn-danger:hover svg{animation:btn-shake .4s ease both;}
.btn-ripple-danger{background:rgba(255,71,87,.35);}

/* Default — SVG wobbles on hover */
.btn:not(.btn-primary):not(.btn-success):not(.btn-danger):not(.btn-login):hover svg{animation:btn-wobble .4s ease both;}
.btn-ripple-default{background:rgba(91,133,255,.25);}

/* Login button */
.btn-login{background:linear-gradient(135deg,var(--primary),var(--primary-light));color:#fff;border:none;
  border-radius:var(--r-sm);padding:14px;font-size:14px;font-weight:700;font-family:'Kanit',sans-serif;
  cursor:pointer;width:100%;min-height:48px;box-shadow:0 4px 20px rgba(59,110,248,.4);transition:transform .15s,box-shadow .15s;
  display:flex;align-items:center;justify-content:center;gap:8px;letter-spacing:.3px;position:relative;overflow:hidden;}
.btn-login:hover{transform:translateY(-1px);box-shadow:0 8px 28px rgba(59,110,248,.6);}

/* FAB Save — spin-once on hover */
#fab-save:hover svg{animation:btn-spin-once .4s cubic-bezier(.34,1.56,.64,1) both;}

.btn-sm{padding:6px 12px;font-size:12px;min-height:32px;}
.btn-full{width:100%;justify-content:center;}
.btn:disabled{opacity:.45;cursor:not-allowed;pointer-events:none;}

/* INPUT */
.input{background:var(--surface2);border:1.5px solid var(--border2);border-radius:var(--r-sm);padding:10px 12px;
  color:var(--text);font-size:14px;font-family:'Kanit',sans-serif;outline:none;width:100%;min-height:44px;transition:border-color .2s,box-shadow .2s;}
.input:focus{border-color:var(--primary-light);box-shadow:0 0 0 3px var(--primary-glow);}
.input::placeholder{color:var(--muted);}
textarea.input{min-height:80px;resize:vertical;}
select.input{cursor:pointer;appearance:none;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8'%3E%3Cpath d='M6 8L0 0h12z' fill='%235a7ba0'/%3E%3C/svg%3E");background-repeat:no-repeat;background-position:right 12px center;}
.field-group{margin-bottom:14px;}
.field-group:last-child{margin-bottom:0;}
.fl-label{font-size:11px;font-weight:600;color:var(--muted2);text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;display:block;}
.chips-wrap{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px;min-height:32px;}
.chip{display:inline-flex;align-items:center;gap:5px;background:var(--surface2);border:1px solid var(--border2);border-radius:20px;padding:4px 10px 4px 12px;font-size:12px;color:var(--text);}
.chip button{background:none;border:none;color:var(--muted);cursor:pointer;font-size:14px;padding:0;transition:color .15s;}
.chip button:hover{color:var(--danger);}

/* TOGGLE ROW */
.trow{display:flex;align-items:center;gap:14px;padding:13px 0;border-bottom:1px solid var(--border);}
.trow:last-child{border-bottom:none;padding-bottom:0;}
.trow:first-child{padding-top:0;}
.trow-ic{font-size:17px;width:26px;height:26px;text-align:center;flex-shrink:0;display:flex;align-items:center;justify-content:center;}
.trow-ic svg{width:15px;height:15px;stroke:var(--muted2);}
.trow-info{flex:1;}
.trow-label{font-size:13px;font-weight:600;color:var(--text);}
.trow-desc{font-size:11px;color:var(--muted);margin-top:2px;}
.badge{padding:2px 8px;border-radius:20px;font-size:10px;font-weight:700;}
.badge-green{background:var(--success-dim);color:var(--success);}
.badge-red{background:var(--danger-dim);color:var(--danger);}
.badge-gray{background:rgba(61,84,120,.2);color:var(--muted2);}

/* LOG CHANNELS */
.logch-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;}
.logch-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--r-sm);padding:13px 15px;
  display:flex;align-items:center;justify-content:space-between;gap:12px;transition:all .2s;}
.logch-card:hover{border-color:var(--border2);transform:translateY(-1px);box-shadow:0 4px 14px rgba(0,0,0,.2);}
.logch-card:hover .logch-ic svg{animation:nav-icon-pop .3s cubic-bezier(.34,1.56,.64,1) both;}
.logch-left{display:flex;align-items:center;gap:11px;}
.logch-ic{font-size:18px;width:26px;text-align:center;}
.logch-name{font-size:13px;font-weight:600;color:var(--text);}
.logch-st{font-size:11px;margin-top:2px;}
.logch-st.has{color:var(--success);}
.logch-st.none{color:var(--muted);}
.sus-dot{display:inline-block;width:7px;height:7px;border-radius:50%;margin-right:5px;vertical-align:middle;}
.logch-ic{width:28px;height:28px;display:flex;align-items:center;justify-content:center;background:var(--surface3);border-radius:7px;color:var(--muted2);flex-shrink:0;}

/* LOGS */
.log-list{display:flex;flex-direction:column;gap:2px;}
.log-item{display:flex;align-items:center;gap:12px;padding:9px 13px;border-radius:8px;transition:background .15s;}
.log-item:hover{background:var(--surface2);}
.log-badge{padding:3px 9px;border-radius:20px;font-size:11px;font-weight:600;white-space:nowrap;flex-shrink:0;}
.log-body{flex:1;min-width:0;}
.log-action{font-size:13px;font-weight:600;color:var(--text);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.log-meta{font-size:11px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.log-time{font-size:11px;color:var(--muted);flex-shrink:0;font-family:'JetBrains Mono',monospace;}

/* SEC HEAD */
.sec-head{font-size:15px;font-weight:700;color:#fff;margin:22px 0 12px;display:flex;align-items:center;gap:8px;}
.sec-head:first-child{margin-top:0;}

/* TOAST */
#toast-wrap{position:fixed;top:18px;right:18px;z-index:9999;display:flex;flex-direction:column;gap:8px;pointer-events:none;}
.toast{background:rgba(17,24,39,.95);border:1px solid var(--border2);border-radius:10px;padding:12px 18px;font-size:12.5px;color:var(--text);backdrop-filter:blur(12px);
  box-shadow:0 8px 28px rgba(0,0,0,.5);animation:toastIn .3s cubic-bezier(.16,1,.3,1) both;max-width:280px;pointer-events:auto;display:flex;align-items:center;gap:8px;}
.toast.success{border-left:3px solid var(--success);background:rgba(0,30,20,.9);}
.toast.error{border-left:3px solid var(--danger);background:rgba(30,8,10,.9);}
.toast.fade-out{animation:toastOut .3s ease both;}

/* FLOATING SAVE */
#fab-save{position:fixed;bottom:24px;right:24px;z-index:999;display:flex;align-items:center;gap:8px;
  background:var(--primary);color:#fff;border:none;border-radius:50px;padding:12px 20px;
  font-size:13px;font-weight:700;font-family:'Kanit',sans-serif;cursor:pointer;
  box-shadow:0 6px 24px rgba(59,110,248,.5);transition:transform .15s,box-shadow .15s,opacity .2s;
  opacity:0;pointer-events:none;}
#fab-save.show{opacity:1;pointer-events:auto;}
#fab-save:hover{transform:translateY(-2px);box-shadow:0 10px 32px rgba(59,110,248,.65);}
#fab-save:active{transform:translateY(0);}

.loader{display:inline-block;width:18px;height:18px;border:2px solid var(--border2);border-top-color:var(--primary-light);border-radius:50%;animation:spin .7s linear infinite;}
.skeleton{background:linear-gradient(90deg,var(--surface) 25%,var(--surface2) 50%,var(--surface) 75%);background-size:600px 100%;animation:shimmer 1.5s infinite;border-radius:6px;color:transparent!important;pointer-events:none;}

/* LOCKDOWN BANNER */
.lockdown-banner{background:linear-gradient(90deg,var(--danger-dim),rgba(255,71,87,.05));border:1px solid rgba(255,71,87,.3);
  border-radius:var(--r);padding:14px 18px;margin-bottom:14px;display:flex;align-items:center;gap:14px;}
.lockdown-banner.hidden{display:none;}
.raid-banner{background:linear-gradient(90deg,rgba(255,140,0,.15),rgba(255,140,0,.03));border:1px solid rgba(255,140,0,.35);
  border-radius:var(--r);padding:14px 18px;margin-bottom:14px;display:flex;align-items:center;gap:14px;}
.raid-banner.hidden{display:none;}
.ld-icon{font-size:28px;}
.ld-info{flex:1;}
.ld-title{font-size:14px;font-weight:700;color:var(--danger);}
.ld-sub{font-size:12px;color:var(--muted2);margin-top:2px;}

/* CATEGORY CARDS */
.cat-card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:14px 16px;cursor:pointer;transition:all .2s;display:flex;flex-direction:column;gap:8px;}
.cat-card:hover{border-color:var(--border2);transform:translateY(-3px);box-shadow:0 6px 24px rgba(0,0,0,.35);}
.cat-card:active{transform:translateY(-1px) scale(.98);}
/* Cat card icon pop on hover */
.cat-card:hover .cat-card-ic svg{animation:nav-icon-pop .35s cubic-bezier(.34,1.56,.64,1) both;}
.cat-card:hover .cat-card-ic{animation:cat-ic-glow .35s ease both;}
@keyframes cat-ic-glow{0%{transform:scale(1)}50%{transform:scale(1.12)}100%{transform:scale(1.08)}}
.cat-card-head{display:flex;align-items:center;gap:10px;}
.cat-card-ic{font-size:22px;width:36px;height:36px;display:flex;align-items:center;justify-content:center;border-radius:10px;flex-shrink:0;}
.cat-card-ic svg{width:18px;height:18px;}
.cat-card-ic.nuke{background:rgba(255,71,87,.12);}
.cat-card-ic.raid{background:rgba(255,165,2,.12);}
.cat-card-ic.spam{background:rgba(59,110,248,.12);}
.cat-card-ic.general{background:rgba(0,200,150,.12);}
.cat-card-name{font-size:13px;font-weight:700;color:#fff;}
.cat-card-desc{font-size:11px;color:var(--muted);}
.cat-card-bar{height:3px;border-radius:2px;background:var(--border2);overflow:hidden;}
.cat-card-bar-fill{height:100%;border-radius:2px;transition:width .5s ease;}
.cat-card-bar-fill.nuke{background:var(--danger);}
.cat-card-bar-fill.raid{background:var(--warn);}
.cat-card-bar-fill.spam{background:var(--primary-light);}
.cat-card-bar-fill.general{background:var(--success);}
.cat-card-footer{display:flex;align-items:center;justify-content:space-between;font-size:11px;color:var(--muted);}
.cat-active-count{font-size:12px;font-weight:700;}
.cat-active-count.nuke{color:var(--danger);}
.cat-active-count.raid{color:var(--warn);}
.cat-active-count.spam{color:var(--primary-light);}
.cat-active-count.general{color:var(--success);}

/* BOTTOM NAV (mobile) */
#bottom-nav{display:none;position:fixed;bottom:0;left:0;right:0;z-index:200;
  padding:0 0 env(safe-area-inset-bottom,8px);
  pointer-events:none;
  background:transparent;}

/* ROLE INSPECTOR */
.ri-role-item{display:flex;align-items:center;gap:10px;padding:10px 14px;background:var(--surface2);
  border:1px solid var(--border);border-radius:var(--r-sm);cursor:pointer;transition:all .18s;}
.ri-role-item:hover{border-color:var(--border2);transform:translateX(4px);}
.ri-role-item:hover .ri-role-dot{animation:btn-ping .4s ease both;}
.ri-role-item:active{transform:translateX(2px) scale(.98);}
.ri-role-dot{width:12px;height:12px;border-radius:50%;flex-shrink:0;}
.ri-role-name{flex:1;font-size:13px;font-weight:600;color:var(--text);}
.ri-role-arrow{color:var(--muted);font-size:12px;}

.ri-ch-row{display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:8px;transition:background .12s;}
.ri-ch-row:hover{background:var(--surface2);}
.ri-ch-icon{font-size:13px;width:20px;text-align:center;flex-shrink:0;}
.ri-ch-name{flex:1;font-size:13px;color:var(--text);}
.ri-ch-cat{font-size:10px;color:var(--muted);}
.ri-ch-badges{display:flex;gap:4px;flex-shrink:0;}
.ri-badge-ok{background:rgba(0,200,150,.12);color:var(--success);border:1px solid rgba(0,200,150,.25);
  border-radius:5px;padding:2px 7px;font-size:10px;font-weight:700;}
.ri-badge-no{background:var(--danger-dim);color:var(--danger);border:1px solid rgba(255,71,87,.25);
  border-radius:5px;padding:2px 7px;font-size:10px;font-weight:700;}
.bnav-inner{
  display:flex;align-items:center;justify-content:center;
  margin:0 16px 10px;
  height:62px;
  background:rgba(18,24,42,0.82);
  backdrop-filter:blur(28px);-webkit-backdrop-filter:blur(28px);
  border:1px solid rgba(255,255,255,0.10);
  border-radius:22px;
  box-shadow:0 8px 32px rgba(0,0,0,0.45),0 1px 0 rgba(255,255,255,0.06) inset;
  pointer-events:all;
  gap:4px;
  padding:0 8px;}
.bnav-item{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3px;cursor:pointer;
  color:rgba(255,255,255,0.38);font-size:10px;font-weight:600;transition:color .18s;
  border-radius:16px;user-select:none;-webkit-tap-highlight-color:transparent;
  padding:6px 2px;position:relative;overflow:hidden;max-width:72px;}
.bnav-item::before{display:none;}
.bnav-item:active{opacity:.7;}
.bnav-item.active{color:rgba(255,255,255,0.95);}
/* Mobile bottom nav — icon pop + bounce on tap */
.bnav-item:active .bnav-ic{animation:bnav-tap .25s cubic-bezier(.34,1.56,.64,1) both;}
@keyframes bnav-tap{0%{transform:scale(1)}40%{transform:scale(.82)}100%{transform:scale(1)}}
.bnav-ic{width:44px;height:30px;display:flex;align-items:center;justify-content:center;
  border-radius:12px;transition:background .18s,transform .18s;}
.bnav-ic svg{width:20px;height:20px;stroke-width:1.8;transition:stroke .15s;}
.bnav-item.active .bnav-ic{background:rgba(91,133,255,0.28);}
.bnav-item.active .bnav-ic svg{stroke:var(--primary-light);}
.bnav-item:active .bnav-ic{transform:scale(.88);}

@media(max-width:768px){
  html,body{height:100%;overflow-x:hidden;}
  #sidebar{display:none;}
  #main{margin-left:0;padding-bottom:calc(80px + env(safe-area-inset-bottom,8px));}
  #bottom-nav{display:flex;}
  .main-head{padding:14px 14px 0;}
  .main-body{padding:14px 14px 24px;}
  .stats-grid{grid-template-columns:repeat(2,1fr);}
  .feature-grid{grid-template-columns:1fr;}
  .logch-grid{grid-template-columns:1fr;}
  #category-cards{grid-template-columns:1fr!important;}
  #fab-save{bottom:calc(88px + env(safe-area-inset-bottom,8px));right:16px;}
}
</style>
</head>
<body>
<div id="toast-wrap"></div>

<!-- LOGIN -->
<div id="login-view">
  <div class="login-card">
    <div class="login-logo">
      <div class="logo-ring"><svg xmlns="http://www.w3.org/2000/svg" width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
      <div>
        <div class="login-title">Security Bot</div>
        <div class="login-sub">กรอกรหัสที่ได้รับจาก DM เพื่อเข้าระบบ</div>
      </div>
    </div>
    <div class="fl">
      <label>รหัสเข้าสู่ระบบ (Token)</label>
      <input class="fi" type="password" id="token-inp" placeholder="วางรหัสที่นี่..." autocomplete="off"/>
    </div>
    <div class="login-err" id="login-err">รหัสไม่ถูกต้องหรือหมดอายุ</div>
    <button class="btn-login" onclick="doLogin()"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg> เข้าสู่ระบบ</button>
    <div class="login-hint">ใช้คำสั่ง <code>/getcode</code> ใน Discord เพื่อรับรหัส</div>
  </div>
</div>

<!-- APP -->
<div id="app-view">
  <nav id="sidebar">
    <div class="sb-head">
      <div class="sb-icon"><svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
      <div><div class="sb-title">Security Bot</div><div class="sb-sub">v2.0 Full</div></div>
    </div>
    <div class="sb-server">
      <div class="sb-sicon" id="sb-icon-wrap"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="8" x="2" y="2" rx="2" ry="2"/><rect width="20" height="8" x="2" y="14" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg></div>
      <div style="min-width:0;">
        <div class="sb-sname" id="sb-sname">กำลังโหลด...</div>
        <div class="sb-sid" id="sb-sid">—</div>
      </div>
    </div>
    <div class="sb-nav">
      <div class="sb-section">ภาพรวม</div>
      <div class="nav-item" onclick="goPage('threat')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg></span>Threat Dashboard</div>
      <div class="nav-item" onclick="goPage('timeline')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><line x1="17" y1="12" x2="3" y2="12"/><polyline points="11 18 17 12 11 6"/><line x1="21" y1="19" x2="21" y2="5"/></svg></span>Action Timeline</div>
      <div class="nav-item" onclick="goPage('weeklyreport')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg></span>Weekly Report</div>
      <div class="nav-item active" onclick="goPage('home')"><div class="nav-dot"></div><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect width="7" height="9" x="3" y="3" rx="1"/><rect width="7" height="5" x="14" y="3" rx="1"/><rect width="7" height="9" x="14" y="12" rx="1"/><rect width="7" height="5" x="3" y="16" rx="1"/></svg></span>หน้าหลัก</div>
      <div class="nav-item" onclick="goPage('logs')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M8 21h12a2 2 0 0 0 2-2v-2H10v2a2 2 0 1 1-4 0V5a2 2 0 1 0-4 0v3h4"/><path d="M19 3H5"/><path d="M14 15H8"/><path d="M14 11H8"/></svg></span>ประวัติ Audit</div>
      <div class="sb-section"><span style="color:var(--danger);opacity:.7;">—</span> Anti-Nuke</div>
      <div class="nav-item" onclick="goPage('antinuke')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg></span>Anti-Nuke</div>
      <div class="sb-section"><span style="color:var(--warn);opacity:.7;">—</span> Anti-Raid</div>
      <div class="nav-item" onclick="goPage('antiraid')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M11 3a1 1 0 1 0 2 0 1 1 0 0 0-2 0"/><path d="M11 21a1 1 0 1 0 2 0 1 1 0 0 0-2 0"/><path d="M3 11a1 1 0 1 0 0 2 1 1 0 0 0 0-2"/><path d="M21 11a1 1 0 1 0 0 2 1 1 0 0 0 0-2"/><path d="m15.5 4.5-2 4.5H11l-2 4.5"/><path d="M12 12a1 1 0 1 0 2 0 1 1 0 0 0-2 0"/><circle cx="12" cy="12" r="9"/></svg></span>Anti-Raid & Gatekeeper</div>
      <div class="nav-item" onclick="goPage('lockdown')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></span>Server Lockdown</div>
      <div class="sb-section"><span style="color:var(--primary-light);opacity:.7;">—</span> Anti-Spam</div>
      <div class="nav-item" onclick="goPage('antispam')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><line x1="9" y1="10" x2="9" y2="10"/><line x1="12" y1="10" x2="12" y2="10"/><line x1="15" y1="10" x2="15" y2="10"/></svg></span>Anti-Spam & Content</div>
      <div class="sb-section"><span style="color:var(--success);opacity:.7;">—</span> ทั่วไป</div>
      <div class="nav-item" onclick="goPage('automod')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2"/><path d="M20 14h2"/><path d="M15 13v2"/><path d="M9 13v2"/></svg></span>Auto Mod</div>
      <div class="nav-item" onclick="goPage('voiceabuse')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2a3 3 0 0 0-3 3v7a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3Z"/><path d="M19 10v2a7 7 0 0 1-14 0v-2"/><line x1="12" y1="19" x2="12" y2="22"/></svg></span>Voice Abuse</div>
      <div class="nav-item" onclick="goPage('welcome')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M13 4h3a2 2 0 0 1 2 2v14"/><path d="M2 20h3"/><path d="M13 20h9"/><path d="M10 12v.01"/><path d="M13 4.562v16.157a1 1 0 0 1-1.242.97L5 20V5.562a2 2 0 0 1 1.515-1.94l4-1A2 2 0 0 1 13 4.561Z"/></svg></span>Welcome</div>
      <div class="nav-item" onclick="goPage('whitelist')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg></span>Whitelist</div>
      <div class="nav-item" onclick="goPage('memberprofile')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="10" cy="8" r="4"/><path d="M10.3 15H7a4 4 0 0 0-4 4v1"/><circle cx="17" cy="16" r="3"/><path d="m21 20-1.9-1.9"/></svg></span>โปรไฟล์สมาชิก</div>
      <div class="nav-item" onclick="goPage('suspicious')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M5.5 8.5 9 12l-3.5 3.5L2 12l3.5-3.5Z"/><path d="m12 2 3.5 3.5L12 9 8.5 5.5 12 2Z"/><path d="M18.5 8.5 22 12l-3.5 3.5L15 12l3.5-3.5Z"/><path d="m12 15 3.5 3.5L12 22l-3.5-3.5L12 15Z"/></svg></span>พฤติกรรมน่าสงสัย</div>
      <div class="nav-item" onclick="goPage('rolemanager')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M4.22 4.22l2.12 2.12M17.66 17.66l2.12 2.12M2 12h3M19 12h3M4.22 19.78l2.12-2.12M17.66 6.34l2.12-2.12"/></svg></span>Role Manager</div>
      <div class="nav-item" onclick="goPage('roleinspector')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2H2v10l9.29 9.29c.94.94 2.48.94 3.42 0l6.58-6.58c.94-.94.94-2.48 0-3.42L12 2Z"/><path d="M7 7h.01"/></svg></span>Role Inspector</div>
      <div class="nav-item" onclick="goPage('userinstall')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="8" r="4"/><path d="M20 21a8 8 0 1 0-16 0"/><line x1="18" y1="11" x2="18" y2="17"/><line x1="15" y1="14" x2="21" y2="14"/></svg></span>User-Install Guard</div>
      <div class="nav-item" onclick="goPage('logchannels')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m3 11 19-9-9 19-2-8-8-2z"/></svg></span>Log Channels</div>
      <div class="nav-item" onclick="goPage('settings')"><span class="nav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg></span>ตั้งค่าทั่วไป</div>
    </div>
    <div class="sb-foot">
      <div class="sb-logout" onclick="doLogout()"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg> ออกจากระบบ</div>
    </div>
  </nav>

  <div id="main">
    <div class="main-head">
      <div>
        <div class="page-title" id="page-title">หน้าหลัก</div>
        <div class="page-sub" id="page-sub">ภาพรวมของ Server</div>
      </div>
      <button class="btn btn-primary btn-sm" onclick="saveConfig()"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:4px;"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg> บันทึก</button>
    </div>
    <div class="main-body">

      <!-- ═══ HOME ═══ -->
      <div class="page active" id="page-home">
        <div class="lockdown-banner hidden" id="ld-banner">
          <div class="ld-icon"><svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="var(--danger)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div>
          <div class="ld-info">
            <div class="ld-title">Server Lockdown เปิดอยู่</div>
            <div class="ld-sub">ทุกห้องถูกล็อก — ลิงก์เชิญถูกยกเลิกทั้งหมด</div>
          </div>
          <button class="btn btn-danger btn-sm" onclick="toggleLockdown(false)"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg> ปลดล็อก</button>
        </div>
        <div class="raid-banner hidden" id="raid-banner">
          <div class="ld-icon"><svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="rgba(255,140,0,.9)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg></div>
          <div class="ld-info">
            <div class="ld-title" style="color:rgba(255,140,0,.9);">⚠️ Raid Mode กำลังทำงาน</div>
            <div class="ld-sub">ตรวจพบการ raid — บอทกำลังบล็อกสมาชิกใหม่อัตโนมัติ</div>
          </div>
        </div>
        <div id="server-banner">
          <!-- [Session 5] รูปพื้นหลัง server (banner/splash) -->
          <img id="banner-img" src="" alt="" style="display:none;">
          <div id="banner-overlay" style="display:none;"></div>
          <div class="banner-bg"></div>
          <div class="banner-content">
            <div class="banner-icon" id="ban-icon"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,.6)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="8" x="2" y="2" rx="2" ry="2"/><rect width="20" height="8" x="2" y="14" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg></div>
            <div class="banner-info">
              <div class="banner-name" id="ban-name"><span class="skeleton" style="width:160px;height:22px;display:inline-block;"></span></div>
              <div class="banner-members" id="ban-members"></div>
            </div>
          </div>
        </div>
        <div class="stats-grid" id="stats-grid">
          <div class="stat-card"><div class="stat-ic"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--primary-light)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M22 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg></div><div class="stat-num skeleton" id="st-members">—</div><div class="stat-label">สมาชิกทั้งหมด</div></div>
          <div class="stat-card"><div class="stat-ic"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--success)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.55a11 11 0 0 1 14.08 0"/><path d="M1.42 9a16 16 0 0 1 21.16 0"/><path d="M8.53 16.11a6 6 0 0 1 6.95 0"/><line x1="12" y1="20" x2="12.01" y2="20"/></svg></div><div class="stat-num skeleton" id="st-online">—</div><div class="stat-label">ออนไลน์</div></div>
          <div class="stat-card"><div class="stat-ic"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--accent)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><line x1="4" y1="9" x2="20" y2="9"/><line x1="4" y1="15" x2="20" y2="15"/><line x1="10" y1="3" x2="8" y2="21"/><line x1="16" y1="3" x2="14" y2="21"/></svg></div><div class="stat-num skeleton" id="st-channels">—</div><div class="stat-label">ช่องทั้งหมด</div></div>
          <div class="stat-card"><div class="stat-ic"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="var(--purple)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2H2v10l9.29 9.29c.94.94 2.48.94 3.42 0l6.58-6.58c.94-.94.94-2.48 0-3.42L12 2Z"/><path d="M7 7h.01"/></svg></div><div class="stat-num skeleton" id="st-roles">—</div><div class="stat-label">ยศทั้งหมด</div></div>
        </div>

        <!-- Category Summary Cards -->
        <div style="font-size:11px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.8px;margin:6px 0 10px;display:flex;align-items:center;gap:6px;"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect width="7" height="7" x="3" y="3" rx="1"/><rect width="7" height="7" x="14" y="3" rx="1"/><rect width="7" height="7" x="14" y="14" rx="1"/><rect width="7" height="7" x="3" y="14" rx="1"/></svg> หมวดหมู่ระบบป้องกัน</div>
        <div id="category-cards" style="display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin-bottom:16px;"></div>

        <!-- Activity Charts -->
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:16px;" id="charts-row">
          <div class="card" style="padding:18px;">
            <div class="card-title" style="margin-bottom:12px;"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>ระบบที่เปิดอยู่</div>
            <div style="position:relative;height:160px;">
              <canvas id="chart-protection"></canvas>
            </div>
          </div>
          <div class="card" style="padding:18px;">
            <div class="card-title" style="margin-bottom:12px;"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg>ภาพรวมเซิร์ฟเวอร์</div>
            <div style="position:relative;height:160px;">
              <canvas id="chart-server"></canvas>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-title"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>สถานะระบบป้องกัน</div>
          <div id="system-status-list"></div>
        </div>
      </div>

      <!-- ═══ ANTI-NUKE ═══ -->
      <div class="page" id="page-antinuke">
        <div class="sec-head"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--danger)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg> Anti-Nuke — ป้องกันผู้ดูแลระบบใช้อำนาจในทางที่ผิด</div>
        <div class="feature-grid" id="grid-antinuke"></div>
      </div>

      <!-- ═══ ANTI-RAID ═══ -->
      <div class="page" id="page-antiraid">
        <div class="sec-head"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--warn)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M11 3a1 1 0 1 0 2 0 1 1 0 0 0-2 0"/><path d="M11 21a1 1 0 1 0 2 0 1 1 0 0 0-2 0"/><path d="M3 11a1 1 0 1 0 0 2 1 1 0 0 0 0-2"/><path d="M21 11a1 1 0 1 0 0 2 1 1 0 0 0 0-2"/><path d="m15.5 4.5-2 4.5H11l-2 4.5"/><path d="M12 12a1 1 0 1 0 2 0 1 1 0 0 0-2 0"/><circle cx="12" cy="12" r="9"/></svg> Anti-Raid & Gatekeeper — สกัดกั้นการโจมตีพร้อมกัน</div>
        <div class="feature-grid" id="grid-antiraid"></div>
      </div>

      <!-- ═══ LOCKDOWN ═══ -->
      <div class="page" id="page-lockdown">
        <div class="sec-head"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--danger)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> Server Lockdown Protocol</div>
        <div class="feature-grid" id="grid-lockdown"></div>
      </div>

      <!-- ═══ ANTI-SPAM ═══ -->
      <div class="page" id="page-antispam">
        <div class="sec-head"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--primary-light)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><line x1="9" y1="10" x2="9" y2="10"/><line x1="12" y1="10" x2="12" y2="10"/><line x1="15" y1="10" x2="15" y2="10"/></svg> Anti-Spam & Content Security</div>
        <div class="feature-grid" id="grid-antispam"></div>
      </div>

      <!-- ═══ AUTO MOD ═══ -->
      <div class="page" id="page-automod">
        <div class="sec-head"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--success)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2"/><path d="M20 14h2"/><path d="M15 13v2"/><path d="M9 13v2"/></svg> Auto Mod — กรองข้อความอัตโนมัติ</div>
        <div class="card">
          <div class="trow" style="padding-top:0;">
            <div class="trow-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--warn)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M13 10V3L4 14h7v7l9-11h-7z"/></svg></div>
            <div class="trow-info"><div class="trow-label">เปิดใช้งาน Auto Mod</div><div class="trow-desc">ตรวจสอบและลบข้อความที่ละเมิดกฎอัตโนมัติ</div></div>
            <label class="tog"><input type="checkbox" id="am-enabled"><span class="tog-sl"></span></label>
          </div>
          <div class="trow">
            <div class="trow-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 17H7A5 5 0 0 1 7 7h2"/><path d="M15 7h2a5 5 0 1 1 0 10h-2"/><line x1="8" y1="12" x2="16" y2="12"/></svg></div>
            <div class="trow-info"><div class="trow-label">กรองลิงก์</div></div>
            <label class="tog"><input type="checkbox" id="am-links"><span class="tog-sl"></span></label>
          </div>
          <div class="trow">
            <div class="trow-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/><line x1="2" y1="2" x2="22" y2="22"/></svg></div>
            <div class="trow-info"><div class="trow-label">กรองลิงก์เชิญ Discord</div></div>
            <label class="tog"><input type="checkbox" id="am-invites"><span class="tog-sl"></span></label>
          </div>
          <div class="trow">
            <div class="trow-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 7 4 4 20 4 20 7"/><line x1="9" y1="20" x2="15" y2="20"/><line x1="12" y1="4" x2="12" y2="20"/></svg></div>
            <div class="trow-info"><div class="trow-label">กรองตัวพิมพ์ใหญ่ (Caps Spam)</div></div>
            <label class="tog"><input type="checkbox" id="am-caps"><span class="tog-sl"></span></label>
          </div>
          <div class="field-group" style="margin-top:12px;">
            <label class="fl-label">บทลงโทษ Auto Mod</label>
            <div class="punish-wrap" id="pun-automod"></div>
          </div>
          <div class="field-group">
            <label class="fl-label">ระยะเวลา Timeout (นาที)</label>
            <input class="input" type="number" id="am-mute-dur" min="1" max="43200" value="5"/>
          </div>
          <div class="field-group">
            <label class="fl-label">คำต้องห้าม (Enter เพื่อเพิ่ม)</label>
            <input class="input" id="bw-inp" type="text" placeholder="พิมพ์คำแล้วกด Enter..."/>
            <div class="chips-wrap" id="bw-chips"></div>
          </div>
        </div>
      </div>

      <!-- ═══ VOICE ABUSE ═══ -->
      <div class="page" id="page-voiceabuse">
        <div class="sec-head"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--purple)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2a3 3 0 0 0-3 3v7a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3Z"/><path d="M19 10v2a7 7 0 0 1-14 0v-2"/><line x1="12" y1="19" x2="12" y2="22"/></svg> Voice Abuse</div>
        <div class="feature-grid" id="grid-voice"></div>
      </div>

      <!-- ═══ WELCOME ═══ -->
      <div class="page" id="page-welcome">
        <div class="card">
          <div class="card-title"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M13 4h3a2 2 0 0 1 2 2v14"/><path d="M2 20h3"/><path d="M13 20h9"/><path d="M10 12v.01"/><path d="M13 4.562v16.157a1 1 0 0 1-1.242.97L5 20V5.562a2 2 0 0 1 1.515-1.94l4-1A2 2 0 0 1 13 4.561Z"/></svg>ข้อความต้อนรับ</div>
          <div class="trow" style="padding-top:0;">
            <div class="trow-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M13 4h3a2 2 0 0 1 2 2v14"/><path d="M2 20h3"/><path d="M13 20h9"/><path d="M10 12v.01"/><path d="M13 4.562v16.157a1 1 0 0 1-1.242.97L5 20V5.562a2 2 0 0 1 1.515-1.94l4-1A2 2 0 0 1 13 4.561Z"/></svg></div>
            <div class="trow-info"><div class="trow-label">เปิดใช้งาน Welcome</div></div>
            <label class="tog"><input type="checkbox" id="wlc-en"><span class="tog-sl"></span></label>
          </div>
          <div class="field-group" style="margin-top:12px;">
            <label class="fl-label">Channel ID ห้อง Welcome</label>
            <input class="input" type="text" id="wlc-ch" placeholder="เช่น 1234567890123456789"/>
          </div>
          <div class="field-group">
            <label class="fl-label">ข้อความ (ใช้ {user}, {server}, {count})</label>
            <textarea class="input" id="wlc-msg" rows="3"></textarea>
          </div>
        </div>
      </div>

      <!-- ═══ WHITELIST ═══ -->
      <div class="page" id="page-whitelist">
        <div class="card">
          <div class="card-title"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--success)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>Whitelist — ข้ามการตรวจสอบทั้งหมด</div>

          <!-- ── เพิ่มยศ ── -->
          <div class="field-group" style="margin-top:0;">
            <label class="fl-label">เพิ่ม / ลบ ยศ</label>
            <div style="display:flex;gap:8px;align-items:center;">
              <select class="input" id="wl-role-select" style="flex:1;">
                <option value="">⏳ กำลังโหลดยศ...</option>
              </select>
              <button class="btn btn-success btn-sm" onclick="wlAddRole()">+ เพิ่ม</button>
            </div>
            <div class="chips-wrap" id="wl-role-chips"></div>
          </div>

          <!-- ── เพิ่มสมาชิก ── -->
          <div class="field-group">
            <label class="fl-label">เพิ่ม / ลบ สมาชิก</label>
            <div style="position:relative;">
              <input class="input" type="text" id="wl-member-search"
                     placeholder="พิมพ์ชื่อ, ชื่อเล่น หรือ ID เพื่อค้นหา..."
                     autocomplete="off" oninput="wlSearchMembers(this.value)"/>
              <div id="wl-member-dropdown"
                   style="display:none;position:absolute;left:0;right:0;top:calc(100% + 4px);
                          background:var(--surface2);border:1.5px solid var(--border2);
                          border-radius:var(--r-sm);z-index:50;max-height:220px;overflow-y:auto;
                          box-shadow:0 8px 24px rgba(0,0,0,.5);">
              </div>
            </div>
            <div class="chips-wrap" id="wl-user-chips"></div>
          </div>

          <!-- ── Bot Whitelist ── -->
          <div class="field-group">
            <label class="fl-label">Bot Whitelist IDs สำหรับ Anti-Bot Add (คั่นด้วย Enter)</label>
            <textarea class="input" id="wl-bots" rows="3" placeholder="Bot IDs ที่อนุญาต..."></textarea>
          </div>

          <!-- ── Save Button ── -->
          <button class="btn btn-primary" style="width:100%;margin-top:8px;" onclick="saveConfig()">
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
            บันทึก Whitelist
          </button>
        </div>
      </div>

      <!-- ═══ LOG CHANNELS ═══ -->
      <div class="page" id="page-logchannels">
        <div class="card">
          <div class="card-title"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="m3 11 19-9-9 19-2-8-8-2z"/></svg>Log Channels</div>
          <div class="field-group" style="margin-top:0;">
            <label class="fl-label">Log Channel หลัก (ID)</label>
            <input class="input" type="text" id="main-log-ch" placeholder="Channel ID"/>
          </div>
          <button class="btn btn-success btn-sm" style="margin-bottom:14px;" onclick="autoCreateLogs()"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m21.64 3.64-1.28-1.28a1.21 1.21 0 0 0-1.72 0L2.36 18.64a1.21 1.21 0 0 0 0 1.72l1.28 1.28a1.2 1.2 0 0 0 1.72 0L21.64 5.36a1.2 1.2 0 0 0 0-1.72Z"/><path d="m14 7 3 3"/><path d="M5 6v4"/><path d="M19 14v4"/><path d="M10 2v2"/><path d="M7 8H3"/><path d="M21 16h-4"/><path d="M11 3H9"/></svg> สร้างห้อง Log อัตโนมัติทั้งหมด</button>
          <div class="logch-grid" id="logch-grid"></div>
        </div>
      </div>

      <!-- ═══ SETTINGS ═══ -->
      <div class="page" id="page-settings">
        <div class="card">
          <div class="card-title"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M20 7H9"/><path d="M14 17H3"/><circle cx="17" cy="17" r="3"/><circle cx="7" cy="7" r="3"/></svg>ตั้งค่าทั่วไป</div>
          <div class="field-group" style="margin-top:0;">
            <label class="fl-label">Blacklist Role ID (สำหรับ Quarantine)</label>
            <div style="display:flex;gap:8px;">
              <input class="input" type="text" id="bl-role-id" placeholder="วาง Role ID หรือกดสร้างอัตโนมัติ" style="flex:1;"/>
              <button class="btn btn-success btn-sm" onclick="sendInitBl()"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m21.64 3.64-1.28-1.28a1.21 1.21 0 0 0-1.72 0L2.36 18.64a1.21 1.21 0 0 0 0 1.72l1.28 1.28a1.2 1.2 0 0 0 1.72 0L21.64 5.36a1.2 1.2 0 0 0 0-1.72Z"/><path d="m14 7 3 3"/><path d="M5 6v4"/><path d="M19 14v4"/><path d="M10 2v2"/><path d="M7 8H3"/><path d="M21 16h-4"/><path d="M11 3H9"/></svg> สร้างอัตโนมัติ</button>
            </div>
          </div>
        </div>
        <div class="card" style="margin-top:4px;">
          <div class="card-title"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>คำสั่ง Bot ที่ใช้ได้</div>
          <div style="display:flex;flex-direction:column;gap:10px;font-size:13px;">
            <div style="background:var(--surface2);border-radius:8px;padding:10px 14px;">
              <code style="color:var(--accent);font-family:'JetBrains Mono',monospace;">/getcode</code>
              <div style="color:var(--muted);font-size:12px;margin-top:3px;">รับรหัสเข้า Dashboard (เจ้าของ Server เท่านั้น)</div>
            </div>
            <div style="background:var(--surface2);border-radius:8px;padding:10px 14px;">
              <code style="color:var(--accent);font-family:'JetBrains Mono',monospace;">/initbl</code>
              <div style="color:var(--muted);font-size:12px;margin-top:3px;">สร้างยศ Blacklist สำหรับ Quarantine อัตโนมัติ</div>
            </div>
            <div style="background:var(--surface2);border-radius:8px;padding:10px 14px;">
              <code style="color:var(--accent);font-family:'JetBrains Mono',monospace;">/lockdown [on/off]</code>
              <div style="color:var(--muted);font-size:12px;margin-top:3px;">เปิด/ปิด Server Lockdown ฉุกเฉินทันที</div>
            </div>
            <div style="background:var(--surface2);border-radius:8px;padding:10px 14px;">
              <code style="color:var(--accent);font-family:'JetBrains Mono',monospace;">/whitelist add user @mention</code>
              <div style="color:var(--muted);font-size:12px;margin-top:3px;">เพิ่มสมาชิกเข้า Whitelist (ข้ามการตรวจทั้งหมด)</div>
            </div>
            <div style="background:var(--surface2);border-radius:8px;padding:10px 14px;">
              <code style="color:var(--accent);font-family:'JetBrains Mono',monospace;">/whitelist add role @role</code>
              <div style="color:var(--muted);font-size:12px;margin-top:3px;">เพิ่มยศเข้า Whitelist</div>
            </div>
            <div style="background:var(--surface2);border-radius:8px;padding:10px 14px;">
              <code style="color:var(--accent);font-family:'JetBrains Mono',monospace;">/whitelist remove user/role @x</code>
              <div style="color:var(--muted);font-size:12px;margin-top:3px;">ลบออกจาก Whitelist</div>
            </div>
            <div style="background:var(--surface2);border-radius:8px;padding:10px 14px;">
              <code style="color:var(--accent);font-family:'JetBrains Mono',monospace;">/whitelist list</code>
              <div style="color:var(--muted);font-size:12px;margin-top:3px;">ดูรายชื่อ Whitelist ทั้งหมด</div>
            </div>
          </div>
        </div>
      </div>

      <!-- ═══ LOGS ═══ -->
      <div class="page" id="page-logs">
        <div class="card" style="padding:0;">
          <div id="log-list" class="log-list" style="padding:8px;"></div>
        </div>
      </div>

      <!-- ═══ MEMBER PROFILE ═══ -->
      <div class="page" id="page-memberprofile">

        <!-- Search -->
        <div class="card" style="margin-bottom:8px;">
          <div class="card-title"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="10" r="3"/><path d="M7 20.662V19a2 2 0 0 1 2-2h6a2 2 0 0 1 2 2v1.662"/></svg>โปรไฟล์สมาชิก &amp; ตั้งค่าการยกเว้น</div>
          <div style="position:relative;">
            <input class="input" type="text" id="mp-search"
                   placeholder="พิมพ์ชื่อ, ชื่อเล่น หรือ ID เพื่อค้นหาสมาชิก..."
                   autocomplete="off" oninput="mpSearch(this.value)"/>
            <div id="mp-dropdown"
                 style="display:none;position:absolute;left:0;right:0;top:calc(100% + 4px);
                        background:var(--surface2);border:1.5px solid var(--border2);
                        border-radius:var(--r-sm);z-index:50;max-height:220px;overflow-y:auto;
                        box-shadow:0 8px 24px rgba(0,0,0,.5);"></div>
          </div>
        </div>

        <!-- Recent members list -->
        <div class="card" style="margin-bottom:8px;">
          <div style="font-size:11px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.6px;margin-bottom:10px;"><svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:4px;"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>สมาชิกที่เคยดูล่าสุด</div>
          <div id="mp-recent-list">
            <div style="color:var(--muted);font-size:13px;text-align:center;padding:18px 0;">ยังไม่มีประวัติการดู — ค้นหาและเลือกสมาชิกด้านบน</div>
          </div>
        </div>

        <!-- Profile panel (hidden until member selected) -->
        <div id="mp-panel" style="display:none;">
          <div class="card" style="margin-bottom:8px;">
            <div style="display:flex;align-items:center;gap:14px;margin-bottom:14px;">
              <img id="mp-avatar" src="" alt=""
                   style="width:62px;height:62px;border-radius:50%;border:2px solid var(--border2);flex-shrink:0;"/>
              <div style="flex:1;min-width:0;">
                <div id="mp-name" style="font-size:16px;font-weight:700;color:#fff;"></div>
                <div id="mp-username" style="font-size:12px;color:var(--muted);"></div>
                <div id="mp-id" style="font-size:11px;color:var(--muted2);font-family:'JetBrains Mono',monospace;margin-top:2px;"></div>
              </div>
              <!-- Gear icon → exemptions panel -->
              <button onclick="mpToggleSettings()" title="ตั้งค่าการยกเว้น"
                      style="background:var(--surface2);border:1px solid var(--border);border-radius:8px;
                             padding:8px 10px;font-size:18px;cursor:pointer;flex-shrink:0;
                             transition:all .15s;" id="mp-gear-btn"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg></button>
            </div>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:14px;">
              <div style="background:var(--surface2);border-radius:8px;padding:10px;">
                <div style="font-size:10px;color:var(--muted2);font-weight:700;text-transform:uppercase;letter-spacing:.5px;">เข้าร่วมเซิร์ฟเวอร์</div>
                <div id="mp-joined" style="font-size:12px;color:var(--text);margin-top:3px;"></div>
              </div>
              <div style="background:var(--surface2);border-radius:8px;padding:10px;">
                <div style="font-size:10px;color:var(--muted2);font-weight:700;text-transform:uppercase;letter-spacing:.5px;">สร้างบัญชี</div>
                <div id="mp-created" style="font-size:12px;color:var(--text);margin-top:3px;"></div>
              </div>
            </div>
            <div>
              <div style="font-size:11px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;">ยศที่มี</div>
              <div id="mp-roles" class="chips-wrap" style="margin-top:0;"></div>
            </div>
          </div>

          <!-- Exemption settings (hidden until gear pressed) -->
          <div class="card" id="mp-settings-panel" style="display:none;margin-bottom:8px;">
            <div class="card-title"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--primary-light)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>ตั้งค่าการยกเว้นการป้องกัน</div>
            <div style="font-size:12px;color:var(--muted);margin-bottom:14px;">เลือกว่าสมาชิกคนนี้จะถูกยกเว้นจากระบบป้องกันใดบ้าง</div>
            <div class="trow" style="padding-top:0;">
              <div class="trow-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="var(--success)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg></div>
              <div class="trow-info"><div class="trow-label">ยกเว้นทั้งหมด (Whitelist เต็ม)</div><div class="trow-desc">ข้ามการตรวจสอบทุกอย่างเหมือนเจ้าของเซิร์ฟเวอร์</div></div>
              <label class="tog"><input type="checkbox" id="ex-all" onchange="exToggleAll(this)"><span class="tog-sl"></span></label>
            </div>
            <div class="trow">
              <div class="trow-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><line x1="12" y1="7" x2="12" y2="11"/><line x1="12" y1="15" x2="12.01" y2="15"/></svg></div>
              <div class="trow-info"><div class="trow-label">ยกเว้น Anti-Spam</div><div class="trow-desc">ไม่ถูกตรวจจับว่าสแปมข้อความ</div></div>
              <label class="tog"><input type="checkbox" id="ex-spam"><span class="tog-sl"></span></label>
            </div>
            <div class="trow">
              <div class="trow-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg></div>
              <div class="trow-info"><div class="trow-label">ยกเว้น Anti-Link Spam</div><div class="trow-desc">สามารถส่งลิงก์ได้โดยไม่ถูกลงโทษ</div></div>
              <label class="tog"><input type="checkbox" id="ex-links"><span class="tog-sl"></span></label>
            </div>
            <div class="trow">
              <div class="trow-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M16 8v5a3 3 0 0 0 6 0v-1a10 10 0 1 0-3.92 7.94"/></svg></div>
              <div class="trow-info"><div class="trow-label">ยกเว้น Anti-Mass Mentions</div><div class="trow-desc">แท็กสมาชิกจำนวนมากได้</div></div>
              <label class="tog"><input type="checkbox" id="ex-mentions"><span class="tog-sl"></span></label>
            </div>
            <div class="trow">
              <div class="trow-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M11 3a1 1 0 1 0 2 0 1 1 0 0 0-2 0"/><path d="M11 21a1 1 0 1 0 2 0 1 1 0 0 0-2 0"/><path d="M3 11a1 1 0 1 0 0 2 1 1 0 0 0 0-2"/><path d="M21 11a1 1 0 1 0 0 2 1 1 0 0 0 0-2"/><circle cx="12" cy="12" r="9"/></svg></div>
              <div class="trow-info"><div class="trow-label">ยกเว้น Anti-Raid / Gatekeeper</div><div class="trow-desc">ไม่ถูกเตะเพราะบัญชีใหม่หรือ join flood</div></div>
              <label class="tog"><input type="checkbox" id="ex-raid"><span class="tog-sl"></span></label>
            </div>
            <div class="trow">
              <div class="trow-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg></div>
              <div class="trow-info"><div class="trow-label">ยกเว้น Anti-Nuke</div><div class="trow-desc">ไม่ถูกตรวจจับการลบห้อง/ยศ/แบนสมาชิก</div></div>
              <label class="tog"><input type="checkbox" id="ex-nuke"><span class="tog-sl"></span></label>
            </div>
            <div class="trow">
              <div class="trow-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2"/><path d="M20 14h2"/><path d="M15 13v2"/><path d="M9 13v2"/></svg></div>
              <div class="trow-info"><div class="trow-label">ยกเว้น Auto Mod</div><div class="trow-desc">ไม่ถูกกรองคำต้องห้าม/ลิงก์/emoji</div></div>
              <label class="tog"><input type="checkbox" id="ex-automod"><span class="tog-sl"></span></label>
            </div>
            <div class="trow">
              <div class="trow-ic"><svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2a3 3 0 0 0-3 3v7a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3Z"/><path d="M19 10v2a7 7 0 0 1-14 0v-2"/><line x1="12" y1="19" x2="12" y2="22"/></svg></div>
              <div class="trow-info"><div class="trow-label">ยกเว้น Voice Abuse</div><div class="trow-desc">ไม่ถูกตรวจจับการย้ายคนใน Voice</div></div>
              <label class="tog"><input type="checkbox" id="ex-voice"><span class="tog-sl"></span></label>
            </div>
            <div style="margin-top:14px;display:flex;gap:8px;">
              <button class="btn btn-primary" style="flex:1;" onclick="mpSaveExemptions()"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg> บันทึกการตั้งค่า</button>
              <button class="btn btn-danger btn-sm" onclick="mpClearExemptions()"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/><line x1="10" y1="11" x2="10" y2="17"/><line x1="14" y1="11" x2="14" y2="17"/></svg> รีเซ็ต</button>
            </div>
          </div>

          <!-- Suspicious Behavior -->
          <div class="card" id="mp-suspicious-panel">
            <div class="card-title"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="var(--warn)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M5.5 8.5 9 12l-3.5 3.5L2 12l3.5-3.5Z"/><path d="m12 2 3.5 3.5L12 9 8.5 5.5 12 2Z"/><path d="M18.5 8.5 22 12l-3.5 3.5L15 12l3.5-3.5Z"/><path d="m12 15 3.5 3.5L12 22l-3.5-3.5L12 15Z"/></svg>พฤติกรรมน่าสงสัย</div>
            <div id="mp-suspicious-list">
              <div style="color:var(--muted);font-size:13px;text-align:center;padding:18px 0;">กำลังวิเคราะห์...</div>
            </div>
          </div>
        </div>
      </div>

      <!-- ═══ SUSPICIOUS BEHAVIOR ALERTS ═══ -->
      <div class="page" id="page-suspicious">
        <div class="card" style="margin-bottom:8px;">
          <div class="card-title"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>แจ้งเตือนพฤติกรรมน่าสงสัย</div>
          <div style="font-size:12px;color:var(--muted);margin-bottom:8px;">บอทตรวจจับพฤติกรรมผิดปกติและแสดงที่นี่ ไม่มีบทลงโทษ — เพียงแจ้งให้ Admin ทราบ</div>
          <div style="display:flex;gap:6px;margin-bottom:4px;">
            <button class="btn btn-sm" id="sus-filter-all" onclick="susFilter('all')" style="flex:1;">ทั้งหมด</button>
            <button class="btn btn-sm" id="sus-filter-high" onclick="susFilter('high')" style="flex:1;color:#ff4757;"><span class="sus-dot" style="background:var(--danger);"></span>สูง</button>
            <button class="btn btn-sm" id="sus-filter-med" onclick="susFilter('med')" style="flex:1;color:#ffa502;"><span class="sus-dot" style="background:var(--warn);"></span>กลาง</button>
            <button class="btn btn-sm" id="sus-filter-low" onclick="susFilter('low')" style="flex:1;color:var(--success);"><span class="sus-dot" style="background:var(--success);"></span>ต่ำ</button>
          </div>
        </div>
        <div id="sus-alert-list" style="display:flex;flex-direction:column;gap:8px;">
          <div style="color:var(--muted);font-size:13px;text-align:center;padding:30px 0;">⏳ กำลังโหลด...</div>
        </div>
      </div>

      <!-- ═══ ROLE MANAGER ═══ -->
      <div class="page" id="page-rolemanager">
        <div class="card" style="margin-bottom:8px;">
          <div class="card-title">
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M4.22 4.22l2.12 2.12M17.66 17.66l2.12 2.12M2 12h3M19 12h3M4.22 19.78l2.12-2.12M17.66 6.34l2.12-2.12"/></svg>
            Role Manager — ตั้งค่าสำหรับ Advanced Lockdown
          </div>
          <div style="font-size:12px;color:var(--muted);margin-bottom:14px;line-height:1.6;">
            ⚡ ตั้งค่านี้จะทำให้ Advanced Lockdown <b style="color:var(--success);">เร็วขึ้นมาก</b> — บอทจะปิดสิทธิ์เฉพาะยศที่ระบุแทนการวน loop ทุกยศใน Server
          </div>

          <!-- Dangerous Roles -->
          <div style="margin-bottom:18px;">
            <div style="font-size:12px;font-weight:700;color:#f85149;margin-bottom:6px;display:flex;align-items:center;gap:6px;">
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
              ยศที่มีสิทธิ์อันตราย (Dangerous Roles)
            </div>
            <div style="font-size:11px;color:var(--muted);margin-bottom:8px;">บอทจะปิดสิทธิ์ของยศเหล่านี้ทันทีเมื่อ Advanced Lockdown ทำงาน</div>
            <div id="rm-dangerous-list" style="display:flex;flex-wrap:wrap;gap:6px;min-height:32px;margin-bottom:8px;"></div>
            <div style="display:flex;gap:8px;align-items:center;">
              <select id="rm-dangerous-select" class="input" style="flex:1;font-size:12px;">
                <option value="">— เลือกยศที่จะเพิ่ม —</option>
              </select>
              <button class="btn btn-sm" onclick="rmAddRole('dangerous')" style="white-space:nowrap;">+ เพิ่ม</button>
            </div>
          </div>

          <!-- Member Roles -->
          <div style="margin-bottom:18px;">
            <div style="font-size:12px;font-weight:700;color:var(--primary-light);margin-bottom:6px;display:flex;align-items:center;gap:6px;">
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
              ยศหลัก / Member Roles
            </div>
            <div style="font-size:11px;color:var(--muted);margin-bottom:8px;">บอทจะไม่แตะยศเหล่านี้เด็ดขาด (ยศ member, verified, ฯลฯ)</div>
            <div id="rm-member-list" style="display:flex;flex-wrap:wrap;gap:6px;min-height:32px;margin-bottom:8px;"></div>
            <div style="display:flex;gap:8px;align-items:center;">
              <select id="rm-member-select" class="input" style="flex:1;font-size:12px;">
                <option value="">— เลือกยศที่จะเพิ่ม —</option>
              </select>
              <button class="btn btn-sm" onclick="rmAddRole('member')" style="white-space:nowrap;">+ เพิ่ม</button>
            </div>
          </div>

          <!-- Exempt Roles -->
          <div style="margin-bottom:18px;">
            <div style="font-size:12px;font-weight:700;color:var(--success);margin-bottom:6px;display:flex;align-items:center;gap:6px;">
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
              ยศละเว้น (Exempt Roles)
            </div>
            <div style="font-size:11px;color:var(--muted);margin-bottom:8px;">บอทจะไม่แตะยศเหล่านี้เด็ดขาด แม้ตอน auto-detect mode</div>
            <div id="rm-exempt-list" style="display:flex;flex-wrap:wrap;gap:6px;min-height:32px;margin-bottom:8px;"></div>
            <div style="display:flex;gap:8px;align-items:center;">
              <select id="rm-exempt-select" class="input" style="flex:1;font-size:12px;">
                <option value="">— เลือกยศที่จะเพิ่ม —</option>
              </select>
              <button class="btn btn-sm" onclick="rmAddRole('exempt')" style="white-space:nowrap;">+ เพิ่ม</button>
            </div>
          </div>

          <button class="btn btn-primary" onclick="rmSave()" id="rm-save-btn" style="width:100%;">
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
            บันทึก Role Manager
          </button>
          <button id="rm-auto-btn" onclick="rmAutoClassify()"
                  style="width:100%;margin-top:8px;padding:10px;background:linear-gradient(135deg,rgba(255,140,0,.15),rgba(255,71,87,.12));
                         border:1px solid rgba(255,140,0,.3);border-radius:10px;color:#ffae00;font-size:13px;
                         font-weight:700;cursor:pointer;transition:all .2s;display:flex;align-items:center;
                         justify-content:center;gap:8px;"
                  onmouseover="this.style.background='linear-gradient(135deg,rgba(255,140,0,.25),rgba(255,71,87,.2))'"
                  onmouseout="this.style.background='linear-gradient(135deg,rgba(255,140,0,.15),rgba(255,71,87,.12))'">
            ⚡ Auto-classify ยศอัตโนมัติ
          </button>
          <div style="font-size:11px;color:var(--muted);text-align:center;margin-top:5px;line-height:1.5;">
            บอทจะวิเคราะห์ทุกยศแล้วแยกอัตโนมัติ — ยศที่มี Permission อันตราย → Dangerous | ยศปกติ → Member
          </div>
          <div id="rm-status" style="margin-top:8px;font-size:12px;text-align:center;min-height:16px;"></div>
        </div>

        <!-- Info card -->
        <div class="card" style="background:rgba(59,110,248,.07);border-color:rgba(59,110,248,.2);">
          <div style="font-size:12px;color:var(--muted);line-height:1.7;">
            <b style="color:var(--primary-light);">💡 วิธีใช้งาน</b><br>
            1. เพิ่มยศที่มี Admin/Manage permissions ลงใน <b style="color:#f85149;">Dangerous Roles</b><br>
            2. เพิ่มยศ member/verified ลงใน <b style="color:var(--primary-light);">Member Roles</b><br>
            3. เพิ่มยศอื่นที่ไม่ต้องการให้บอทแตะลงใน <b style="color:var(--success);">Exempt Roles</b><br>
            4. กด <b>บันทึก</b> — Advanced Lockdown จะเร็วขึ้นทันที
          </div>
        </div>
      </div>

      <!-- ═══ ROLE INSPECTOR ═══ -->
      <div class="page" id="page-roleinspector">
        <div class="card" style="margin-bottom:8px;">
          <div class="card-title"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M12 2H2v10l9.29 9.29c.94.94 2.48.94 3.42 0l6.58-6.58c.94-.94.94-2.48 0-3.42L12 2Z"/><path d="M7 7h.01"/></svg>Role Inspector — ดูสิทธิ์ห้องของยศ</div>
          <div style="font-size:12px;color:var(--muted);margin-bottom:12px;">เลือกยศเพื่อดูว่ายศนั้นเห็น/พิมพ์ในห้องใดได้บ้าง</div>
          <div id="ri-role-list" style="display:flex;flex-direction:column;gap:6px;"></div>
        </div>

        <!-- Channel permission panel -->
        <div id="ri-panel" style="display:none;">
          <div class="card">
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;">
              <div>
                <div id="ri-role-name" style="font-size:15px;font-weight:700;color:#fff;"></div>
                <div style="font-size:11px;color:var(--muted);margin-top:2px;">
                  <span id="ri-can-count" style="color:var(--success);font-weight:600;"></span>
                  <span style="margin:0 6px;">•</span>
                  <span id="ri-cant-count" style="color:var(--danger);font-weight:600;"></span>
                </div>
              </div>
              <button class="btn btn-sm" onclick="riClose()"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg> ปิด</button>
            </div>

            <!-- Filter -->
            <div style="display:flex;gap:6px;margin-bottom:12px;">
              <button class="btn btn-sm" id="ri-filter-all" onclick="riFilter('all')" style="flex:1;">ทั้งหมด</button>
              <button class="btn btn-sm" id="ri-filter-can" onclick="riFilter('can')" style="flex:1;color:var(--success);"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg> เห็น</button>
              <button class="btn btn-sm" id="ri-filter-cant" onclick="riFilter('cant')" style="flex:1;color:var(--danger);"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg> ไม่เห็น</button>
            </div>

            <div id="ri-channel-list" style="display:flex;flex-direction:column;gap:4px;max-height:480px;overflow-y:auto;"></div>
          </div>
        </div>
      </div>

      <!-- ════════════════════════════════════════════════════════
           USER-INSTALL GUARD PAGE
           ════════════════════════════════════════════════════════ -->
      <div class="page" id="page-userinstall">

        <!-- อธิบาย Feature -->
        <div class="card" style="margin-bottom:12px;border-left:3px solid #ff4757;">
          <div class="card-title" style="color:#ff6b81;">
            <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><circle cx="12" cy="8" r="4"/><path d="M20 21a8 8 0 1 0-16 0"/><line x1="18" y1="11" x2="18" y2="17"/><line x1="15" y1="14" x2="21" y2="14"/></svg>
            User-Install Guard — ป้องกัน User-Installed Apps
          </div>
          <div style="font-size:12px;color:var(--muted);line-height:1.6;">
            <b style="color:var(--text);">User-Installable Apps</b> คือระบบของ Discord ที่ให้ user ติดตั้งบอทเข้าโปรไฟล์ตัวเอง
            แล้วใช้ Slash Command ได้ใน <b>ทุก server</b> โดยไม่ต้องเชิญบอทเข้า server<br><br>
            ⚠️ ความเสี่ยง: บางคนนำระบบนี้ไปใช้ส่งข้อความรัวๆ หรือ spam ผ่าน slash command
            ในช่องที่บอทของ server ตรวจไม่ถึง เพราะบอทไม่ได้อยู่ใน server จริงๆ<br><br>
            ✅ feature นี้จะตรวจจับและจัดการทุก interaction ที่มาจาก User-Installed App ใน server นี้
          </div>
        </div>

        <!-- Config Card -->
        <div class="card" id="ui-config-card">
          <div class="card-title">
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg>
            ตั้งค่า
          </div>

          <div class="feat-row" style="margin-bottom:14px;">
            <div>
              <div style="font-weight:600;font-size:13px;">เปิดใช้งาน User-Install Guard</div>
              <div style="font-size:11px;color:var(--muted);">ตรวจและจัดการ slash command จาก User-Installed App ทันที</div>
            </div>
            <label class="toggle"><input type="checkbox" id="ui-enabled"><span class="slider"></span></label>
          </div>

          <div style="margin-bottom:14px;">
            <div style="font-size:12px;color:var(--muted);margin-bottom:8px;font-weight:600;">Action เมื่อตรวจพบ</div>
            <div style="display:flex;gap:8px;flex-wrap:wrap;">
              <label style="display:flex;align-items:center;gap:6px;cursor:pointer;font-size:13px;">
                <input type="radio" name="ui-action" value="delete" id="ui-act-delete"> แจ้งเตือน &amp; ยกเลิก
              </label>
              <label style="display:flex;align-items:center;gap:6px;cursor:pointer;font-size:13px;">
                <input type="radio" name="ui-action" value="warn" id="ui-act-warn"> แจ้งเตือนอย่างเดียว
              </label>
              <label style="display:flex;align-items:center;gap:6px;cursor:pointer;font-size:13px;">
                <input type="radio" name="ui-action" value="timeout" id="ui-act-timeout"> Timeout
              </label>
            </div>
          </div>

          <div id="ui-timeout-row" style="margin-bottom:14px;display:none;">
            <div style="font-size:12px;color:var(--muted);margin-bottom:6px;font-weight:600;">ระยะเวลา Timeout (วินาที)</div>
            <input type="number" id="ui-timeout-sec" min="30" max="2419200" value="300"
              style="background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:6px 10px;color:var(--text);font-size:13px;width:120px;">
          </div>

          <div class="feat-row" style="margin-bottom:14px;">
            <div>
              <div style="font-weight:600;font-size:13px;">บันทึก Log ลงห้อง Log</div>
              <div style="font-size:11px;color:var(--muted);">ส่ง embed แจ้งเตือนทุกครั้งที่ตรวจพบ</div>
            </div>
            <label class="toggle"><input type="checkbox" id="ui-log" checked><span class="slider"></span></label>
          </div>

          <button class="btn btn-primary" onclick="uiSave()" style="width:100%;">
            <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
            บันทึก
          </button>
        </div>

        <!-- Whitelist Apps -->
        <div class="card" style="margin-top:12px;">
          <div class="card-title">
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>
            Whitelist Application IDs
          </div>
          <div style="font-size:12px;color:var(--muted);margin-bottom:10px;">
            App ID ที่อนุญาตให้ใช้ได้แม้จะเป็น User-Installed (กรอก Application ID ของบอทนั้น)
          </div>
          <div id="ui-app-list" style="display:flex;flex-direction:column;gap:6px;margin-bottom:10px;"></div>
          <div style="display:flex;gap:8px;">
            <input type="text" id="ui-app-input" placeholder="Application ID (เช่น 123456789)" maxlength="25"
              style="flex:1;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:6px 10px;color:var(--text);font-size:13px;">
            <button class="btn btn-sm btn-primary" onclick="uiAddApp()">เพิ่ม</button>
          </div>
        </div>

        <!-- Whitelist Users -->
        <div class="card" style="margin-top:12px;">
          <div class="card-title">
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><circle cx="12" cy="8" r="4"/><path d="M20 21a8 8 0 1 0-16 0"/></svg>
            Whitelist User IDs
          </div>
          <div style="font-size:12px;color:var(--muted);margin-bottom:10px;">
            User ที่อนุญาตให้ใช้ User-Installed App ใน server นี้ได้
          </div>
          <div id="ui-user-list" style="display:flex;flex-direction:column;gap:6px;margin-bottom:10px;"></div>
          <div style="display:flex;gap:8px;">
            <input type="text" id="ui-user-input" placeholder="User ID (เช่น 987654321)" maxlength="25"
              style="flex:1;background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:6px 10px;color:var(--text);font-size:13px;">
            <button class="btn btn-sm btn-primary" onclick="uiAddUser()">เพิ่ม</button>
          </div>
        </div>

      </div><!-- /page-userinstall -->

      <!-- ═══ THREAT DASHBOARD ═══ -->
      <div class="page" id="page-threat">
        <div class="sec-head"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--danger)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg> Threat Dashboard — ภาพรวม Real-time</div>

        <!-- Live Status Row -->
        <div class="card" style="margin-bottom:12px;padding:14px 16px;">
          <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px;">
            <div style="display:flex;align-items:center;gap:10px;">
              <span class="threat-live-dot" id="td-live-dot" style="background:var(--success);"></span>
              <span style="font-size:13px;font-weight:700;" id="td-live-label">ระบบทำงานปกติ</span>
            </div>
            <div style="display:flex;gap:16px;">
              <div style="text-align:center;">
                <div style="font-size:18px;font-weight:800;color:var(--danger);" id="td-ban-count">—</div>
                <div style="font-size:10px;color:var(--muted);">แบนวันนี้</div>
              </div>
              <div style="text-align:center;">
                <div style="font-size:18px;font-weight:800;color:var(--warn);" id="td-kick-count">—</div>
                <div style="font-size:10px;color:var(--muted);">เตะวันนี้</div>
              </div>
              <div style="text-align:center;">
                <div style="font-size:18px;font-weight:800;color:var(--primary-light);" id="td-event-count">—</div>
                <div style="font-size:10px;color:var(--muted);">events ทั้งหมด</div>
              </div>
            </div>
          </div>
        </div>

        <!-- Gauge Row -->
        <div class="threat-grid" id="td-gauge-grid">
          <div class="threat-gauge">
            <div class="gauge-ring">
              <svg viewBox="0 0 80 80"><circle class="gauge-bg" cx="40" cy="40" r="32"/><circle class="gauge-fill" id="gf-nuke" cx="40" cy="40" r="32" stroke="#ff4757" stroke-dasharray="201" stroke-dashoffset="201"/></svg>
              <div class="gauge-val" id="gv-nuke">0%</div>
            </div>
            <div class="gauge-label">Anti-Nuke</div>
            <div class="gauge-sub" id="gs-nuke">0/16 เปิด</div>
          </div>
          <div class="threat-gauge">
            <div class="gauge-ring">
              <svg viewBox="0 0 80 80"><circle class="gauge-bg" cx="40" cy="40" r="32"/><circle class="gauge-fill" id="gf-raid" cx="40" cy="40" r="32" stroke="#ffa502" stroke-dasharray="201" stroke-dashoffset="201"/></svg>
              <div class="gauge-val" id="gv-raid">0%</div>
            </div>
            <div class="gauge-label">Anti-Raid</div>
            <div class="gauge-sub" id="gs-raid">0/4 เปิด</div>
          </div>
          <div class="threat-gauge">
            <div class="gauge-ring">
              <svg viewBox="0 0 80 80"><circle class="gauge-bg" cx="40" cy="40" r="32"/><circle class="gauge-fill" id="gf-spam" cx="40" cy="40" r="32" stroke="#5585ff" stroke-dasharray="201" stroke-dashoffset="201"/></svg>
              <div class="gauge-val" id="gv-spam">0%</div>
            </div>
            <div class="gauge-label">Anti-Spam</div>
            <div class="gauge-sub" id="gs-spam">0/5 เปิด</div>
          </div>
        </div>

        <!-- Level Bars -->
        <div class="card" style="margin-bottom:12px;">
          <div class="card-title" style="margin-bottom:12px;"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 9h18M9 21V9"/></svg>ระดับความพร้อมรับมือ</div>
          <div id="td-bars"></div>
        </div>

        <!-- System States -->
        <div class="card">
          <div class="card-title" style="margin-bottom:10px;"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>สถานะระบบพิเศษ</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;" id="td-states">
            <div class="trow" style="background:var(--surface2);border-radius:8px;padding:10px 12px;flex-direction:column;gap:4px;align-items:flex-start;">
              <div style="font-size:11px;font-weight:700;color:var(--muted2);">Server Lockdown</div>
              <span class="badge badge-gray" id="td-lockdown-badge">ปิด</span>
            </div>
            <div class="trow" style="background:var(--surface2);border-radius:8px;padding:10px 12px;flex-direction:column;gap:4px;align-items:flex-start;">
              <div style="font-size:11px;font-weight:700;color:var(--muted2);">Raid Mode</div>
              <span class="badge badge-gray" id="td-raidmode-badge">ปกติ</span>
            </div>
          </div>
        </div>
      </div>

      <!-- ═══ ACTION TIMELINE ═══ -->
      <div class="page" id="page-timeline">
        <div class="sec-head"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--primary-light)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><line x1="17" y1="12" x2="3" y2="12"/><polyline points="11 18 17 12 11 6"/><line x1="21" y1="19" x2="21" y2="5"/></svg> Action Timeline — ประวัติเหตุการณ์</div>
        <div class="card" style="margin-bottom:12px;">
          <div class="tl-filter-row" id="tl-filters">
            <button class="tl-filter-btn active" onclick="tlFilter('all')">ทั้งหมด</button>
            <button class="tl-filter-btn" onclick="tlFilter('ban')">แบน</button>
            <button class="tl-filter-btn" onclick="tlFilter('kick')">เตะ</button>
            <button class="tl-filter-btn" onclick="tlFilter('raid')">Raid</button>
            <button class="tl-filter-btn" onclick="tlFilter('nuke')">Nuke</button>
            <button class="tl-filter-btn" onclick="tlFilter('spam')">Spam</button>
          </div>
          <div style="display:flex;gap:8px;">
            <input class="input" type="text" id="tl-search" placeholder="ค้นหา user หรือ action..." oninput="tlSearch(this.value)" style="font-size:12px;"/>
            <button class="btn btn-sm" onclick="loadTimeline()"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-.18-5.2"/></svg></button>
          </div>
        </div>
        <div class="timeline-wrap" id="tl-list">
          <div class="tl-empty">⏳ กำลังโหลด...</div>
        </div>
        <div style="text-align:center;margin-top:16px;" id="tl-load-more-wrap">
          <button class="btn btn-sm" id="tl-load-more" onclick="tlLoadMore()" style="display:none;">โหลดเพิ่มเติม</button>
        </div>
      </div>

      <!-- ═══ WEEKLY REPORT ═══ -->
      <div class="page" id="page-weeklyreport">
        <div class="sec-head"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--success)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="20" x2="18" y2="10"/><line x1="12" y1="20" x2="12" y2="4"/><line x1="6" y1="20" x2="6" y2="14"/></svg> Weekly Report — สรุปรายสัปดาห์</div>

        <!-- Week navigation -->
        <div class="report-week-nav">
          <button onclick="wrChangeWeek(-1)">&#8249;</button>
          <div class="report-week-label" id="wr-week-label">สัปดาห์นี้</div>
          <button onclick="wrChangeWeek(1)" id="wr-next-btn">&#8250;</button>
        </div>

        <!-- Hero -->
        <div class="report-hero">
          <div class="report-hero-ic"><svg xmlns="http://www.w3.org/2000/svg" width="26" height="26" viewBox="0 0 24 24" fill="none" stroke="var(--primary-light)" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg></div>
          <div class="report-hero-text">
            <h2 id="wr-title">สัปดาห์นี้</h2>
            <p id="wr-subtitle">กำลังคำนวณจากประวัติ logs...</p>
          </div>
        </div>

        <!-- KPI Grid -->
        <div class="report-kpi-grid">
          <div class="report-kpi">
            <div class="report-kpi-num" style="color:var(--danger);" id="wr-bans">—</div>
            <div class="report-kpi-label">แบนทั้งหมด</div>
            <div class="report-kpi-trend" id="wr-bans-trend"></div>
          </div>
          <div class="report-kpi">
            <div class="report-kpi-num" style="color:var(--warn);" id="wr-kicks">—</div>
            <div class="report-kpi-label">เตะทั้งหมด</div>
            <div class="report-kpi-trend" id="wr-kicks-trend"></div>
          </div>
          <div class="report-kpi">
            <div class="report-kpi-num" style="color:var(--primary-light);" id="wr-total">—</div>
            <div class="report-kpi-label">events ทั้งหมด</div>
            <div class="report-kpi-trend" id="wr-total-trend"></div>
          </div>
          <div class="report-kpi">
            <div class="report-kpi-num" style="color:var(--success);" id="wr-safe-pct">—</div>
            <div class="report-kpi-label">ป้องกันได้ (%)</div>
            <div class="report-kpi-trend" id="wr-safe-trend"></div>
          </div>
        </div>

        <!-- Top triggered systems -->
        <div class="card" style="margin-bottom:12px;">
          <div class="card-title" style="margin-bottom:12px;"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M13 10V3L4 14h7v7l9-11h-7z"/></svg>ระบบที่ทำงานบ่อยที่สุด</div>
          <div id="wr-top-systems"></div>
        </div>

        <!-- Daily chart -->
        <div class="card">
          <div class="card-title" style="margin-bottom:12px;"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>กิจกรรมรายวัน</div>
          <div style="position:relative;height:140px;"><canvas id="wr-daily-chart"></canvas></div>
        </div>
      </div>



  <!-- BOTTOM NAV -->
  <nav id="bottom-nav">
    <div class="bnav-inner">
      <div class="bnav-item active" onclick="goPage('home')"><div class="bnav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect width="7" height="9" x="3" y="3" rx="1"/><rect width="7" height="5" x="14" y="3" rx="1"/><rect width="7" height="9" x="14" y="12" rx="1"/><rect width="7" height="5" x="3" y="16" rx="1"/></svg></div>หลัก</div>
      <div class="bnav-item" onclick="goPage('antinuke')"><div class="bnav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg></div>Nuke</div>
      <div class="bnav-item" onclick="goPage('antiraid')"><div class="bnav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M11 3a1 1 0 1 0 2 0 1 1 0 0 0-2 0"/><path d="M11 21a1 1 0 1 0 2 0 1 1 0 0 0-2 0"/><path d="M3 11a1 1 0 1 0 0 2 1 1 0 0 0 0-2"/><path d="M21 11a1 1 0 1 0 0 2 1 1 0 0 0 0-2"/><circle cx="12" cy="12" r="9"/></svg></div>Raid</div>
      <div class="bnav-item" onclick="goPage('antispam')"><div class="bnav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><line x1="9" y1="10" x2="9" y2="10"/><line x1="12" y1="10" x2="12" y2="10"/><line x1="15" y1="10" x2="15" y2="10"/></svg></div>Spam</div>
      <div class="bnav-item" onclick="goPage('settings')"><div class="bnav-ic"><svg xmlns="http://www.w3.org/2000/svg" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg></div>ตั้งค่า</div>
    </div>
  </nav>
</div><!-- /app-view -->

<script>
// ─── CONFIG ───────────────────────────────────────────────────────
const API_BASE = "http://localhost:8080";
let CFG = {};
let logChConfig = {};
let savedWords = [];
let wlRoleIds  = [];
let wlUserIds  = [];
let wlRoleData = [];
let wlUserData = {};

const getToken = () => sessionStorage.getItem('sb_token') || '';

async function apiFetch(path, method='GET', body=null) {
  const url = `${API_BASE}${path}?token=${encodeURIComponent(getToken())}`;
  const opts = { method, headers: { 'Content-Type': 'application/json' } };
  if (body) opts.body = JSON.stringify(body);
  const r = await fetch(url, opts);
  if (r.status === 401) {
    handleSessionExpired();
    throw new Error('Session หมดอายุ');
  }
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

let _sessionExpiredNotified = false;
function handleSessionExpired() {
  if (_sessionExpiredNotified) return;
  _sessionExpiredNotified = true;
  toast('⚠️ Session หมดอายุ — กรุณาขอ /getcode ใหม่ กำลัง logout...', 'error', 4000);
  setTimeout(() => {
    sessionStorage.removeItem('sb_token');
    location.reload();
  }, 3000);
}
const setToken = t => sessionStorage.setItem('sb_token', t);

// ─── PUNISHMENT OPTIONS ───────────────────────────────────────────
const PUNISHMENTS = [
  {val:'ban',        ic:'<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 3H5a2 2 0 0 0-2 2v4m6-6h10a2 2 0 0 1 2 2v4M9 3v11m0 0H5a2 2 0 0 1-2-2V9m6 5h10a2 2 0 0 0 2-2V9m0 0H3"/></svg>', label:'แบน',        cls:'p-ban'},
  {val:'kick',       ic:'<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 0 1-3 3H6a3 3 0 0 1-3-3V7a3 3 0 0 1 3-3h4a3 3 0 0 1 3 3v1"/></svg>', label:'เตะ',         cls:'p-kick'},
  {val:'quarantine', ic:'<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>', label:'กักบริเวณ',  cls:'p-quarantine'},
  {val:'timeout',    ic:'<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>', label:'Timeout',    cls:'p-timeout'},
  {val:'log',        ic:'<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14.5 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V7.5L14.5 2z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><line x1="10" y1="9" x2="8" y2="9"/></svg>', label:'Log Only',   cls:'p-log'},
];

function buildPunishWrap(wrapperId, currentVal) {
  const wrap = document.getElementById(wrapperId);
  if (!wrap) return;
  wrap.dataset.val = currentVal || 'timeout';
  wrap.innerHTML = PUNISHMENTS.map(p => `
    <div class="punish-btn ${p.cls} ${currentVal===p.val?'sel':''}"
         onclick="(function(el){
           document.getElementById('${wrapperId}').querySelectorAll('.punish-btn').forEach(b=>b.classList.remove('sel'));
           el.classList.add('sel');
           document.getElementById('${wrapperId}').dataset.val='${p.val}';
         })(this)">
      <div class="punish-ic">${p.ic}</div>${p.label}
    </div>`).join('');
}

// ─── FEATURE CARD BUILDER ─────────────────────────────────────────
// Each feature gets its own card with: toggle, limit, window, punishment
function buildFeatureCard(key, emoji, name, desc, cfg, extraFields='') {
  const feat = cfg[key] || {};
  const checked = feat.enabled ? 'checked' : '';
  const limit  = feat.limit  ?? 3;
  const windowSec = feat.window ?? 10;
  const punish  = feat.punishment || 'ban';
  // แปลง window เป็น display + unit
  let windowDisplay, windowUnit;
  if (windowSec % 3600 === 0 && windowSec >= 3600) { windowDisplay = windowSec/3600; windowUnit = 'h'; }
  else if (windowSec % 60 === 0 && windowSec >= 60) { windowDisplay = windowSec/60;   windowUnit = 'm'; }
  else { windowDisplay = windowSec; windowUnit = 's'; }
  // timeout duration
  const timeoutDurSec = feat.timeout_duration ?? 300;
  let timeoutDurDisplay, timeoutUnit;
  if (timeoutDurSec % 86400 === 0) { timeoutDurDisplay = timeoutDurSec/86400; timeoutUnit = 'd'; }
  else if (timeoutDurSec % 3600 === 0) { timeoutDurDisplay = timeoutDurSec/3600; timeoutUnit = 'h'; }
  else if (timeoutDurSec % 60 === 0)   { timeoutDurDisplay = timeoutDurSec/60;   timeoutUnit = 'm'; }
  else { timeoutDurDisplay = timeoutDurSec; timeoutUnit = 's'; }
  const window_ = windowSec;
  const punishOpts = PUNISHMENTS.map(p =>
    `<div class="punish-btn ${p.cls} ${punish===p.val?'sel':''}"
       onclick="selectFeatPunish('${key}',this,'${p.val}','${p.cls}')" >
       <div class="punish-ic">${p.ic}</div>${p.label}
     </div>`).join('');

  return `
  <div class="feat-card ${feat.enabled?'enabled':''}" id="fcard-${key}">
    <div class="feat-header">
      <div class="feat-emoji">${emoji}</div>
      <div class="feat-label">
        <div class="feat-name">${name}</div>
        <div class="feat-desc">${desc}</div>
      </div>
      <label class="tog">
        <input type="checkbox" id="feat-en-${key}" ${checked}
               onchange="toggleFeatCard('${key}',this.checked)">
        <span class="tog-sl"></span>
      </label>
    </div>
    <div class="feat-body">
      <div class="sub-field">
        <div class="sub-label">บทลงโทษ</div>
        <div class="punish-wrap" id="punish-${key}" data-val="${punish}">${punishOpts}</div>
      </div>
      <div class="sub-field">
        <div class="sub-label">ขีดจำกัดจำนวนครั้ง (Threshold)</div>
        <div class="sub-row">
          <input class="sub-input" type="number" id="feat-limit-${key}" min="1" max="100" value="${limit}">
          <span class="sub-unit">ครั้ง</span>
        </div>
      </div>
      <div class="sub-field">
        <div class="sub-label">ช่วงเวลา (Time Window)</div>
        <div class="sub-row">
          <input class="sub-input" type="number" id="feat-window-${key}" min="1" max="86400" value="${windowDisplay}">
          <select class="sub-select" id="feat-window-unit-${key}" onchange="updateWindowUnit('${key}')">
            <option value="s" ${windowUnit==='s'?'selected':''}>วินาที</option>
            <option value="m" ${windowUnit==='m'?'selected':''}>นาที</option>
            <option value="h" ${windowUnit==='h'?'selected':''}>ชั่วโมง</option>
          </select>
        </div>
      </div>
      <div class="sub-field" id="timeout-dur-field-${key}" style="display:${punish==='timeout'?'block':'none'}">
        <div class="sub-label">ระยะเวลา Timeout</div>
        <div class="sub-row">
          <input class="sub-input" type="number" id="feat-timeout-dur-${key}" min="1" max="40320" value="${timeoutDurDisplay}">
          <select class="sub-select" id="feat-timeout-unit-${key}">
            <option value="s" ${timeoutUnit==='s'?'selected':''}>วินาที</option>
            <option value="m" ${timeoutUnit==='m'?'selected':''}>นาที</option>
            <option value="h" ${timeoutUnit==='h'?'selected':''}>ชั่วโมง</option>
            <option value="d" ${timeoutUnit==='d'?'selected':''}>วัน</option>
          </select>
        </div>
      </div>
      ${extraFields}
    </div>
    <div class="adv-toggle-row" id="adv-row-${key}">
      <div class="adv-toggle-ic">
        <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12h6"/><path d="M12 9v6"/></svg>
      </div>
      <div class="adv-toggle-info">
        <div class="adv-toggle-label">จัดการขั้นสูง</div>
        <div class="adv-toggle-desc">ปิด permission ผู้ดูแลทันที &#x2192; ตรวจ &#x2192; ลงโทษ &#x2192; คืนอัตโนมัติ</div>
      </div>
      <label class="tog">
        <input type="checkbox" id="adv-en-${key}"
               onchange="onAdvToggle('${key}', this.checked)">
        <span class="tog-sl"></span>
      </label>
    </div>
  </div>`;
}

function toggleFeatCard(key, on) {
  const card = document.getElementById('fcard-' + key);
  if (card) card.classList.toggle('enabled', on);
}

function selectFeatPunish(key, el, val, cls) {
  const wrap = document.getElementById('punish-' + key);
  wrap.querySelectorAll('.punish-btn').forEach(b => b.classList.remove('sel'));
  el.classList.add('sel');
  wrap.dataset.val = val;
  // แสดง/ซ่อน timeout duration field
  const durField = document.getElementById('timeout-dur-field-' + key);
  if (durField) durField.style.display = val === 'timeout' ? 'block' : 'none';
}

function updateWindowUnit(key) {
  // ไม่ต้องทำอะไรตอนนี้ — getFeatVal จะอ่านค่า unit เอง
}

// ── helper: แปลง display value + unit → วินาที ──
function toSeconds(val, unit) {
  const v = parseInt(val) || 1;
  if (unit === 'm') return v * 60;
  if (unit === 'h') return v * 3600;
  if (unit === 'd') return v * 86400;
  return v;
}

// ── ตรวจสอบห้องที่ถูกลบ ──
async function validateChannels() {
  try {
    const r = await fetch(`${API_BASE}/api/channels/validate?token=${encodeURIComponent(getToken())}`);
    const data = await r.json();
    if (!data.missing || data.missing.length === 0) return;
    // สร้าง banner แจ้งเตือน
    const existing = document.getElementById('ch-missing-banner');
    if (existing) existing.remove();
    const banner = document.createElement('div');
    banner.id = 'ch-missing-banner';
    banner.style.cssText = 'position:fixed;bottom:16px;left:50%;transform:translateX(-50%);background:#1e1e2e;border:1px solid #f85149;border-radius:10px;padding:12px 16px;z-index:9999;max-width:360px;width:90%;box-shadow:0 4px 20px rgba(0,0,0,.5);';
    banner.innerHTML = `
      <div style="font-size:12px;font-weight:700;color:#f85149;margin-bottom:8px;">⚠️ พบห้องที่ถูกลบออกจาก Discord</div>
      <div style="font-size:11px;color:#a0a0b0;margin-bottom:10px;line-height:1.6;">
        ${data.missing.map(m => `• ${escHtml(m.label)}`).join('<br>')}
      </div>
      <div style="display:flex;gap:8px;">
        <button onclick="clearMissingChannels(${JSON.stringify(data.missing).replace(/"/g,'&quot;')})" 
                style="flex:1;background:#f85149;color:#fff;border:none;border-radius:6px;padding:6px;font-size:11px;cursor:pointer;">
          ลบออกจาก Config
        </button>
        <button onclick="document.getElementById('ch-missing-banner').remove()"
                style="flex:1;background:rgba(255,255,255,.08);color:#a0a0b0;border:none;border-radius:6px;padding:6px;font-size:11px;cursor:pointer;">
          ไว้ก่อน
        </button>
      </div>`;
    document.body.appendChild(banner);
  } catch(e) { console.error('validateChannels', e); }
}

async function clearMissingChannels(items) {
  try {
    await fetch(`${API_BASE}/api/channels/clear?token=${encodeURIComponent(getToken())}`, {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({ items }),
    });
    document.getElementById('ch-missing-banner')?.remove();
    toast('✅ ลบห้องที่หายไปออกจาก config แล้ว', 'success');
    await loadConfig();
  } catch(e) { toast('❌ ' + e.message, 'error'); }
}

// ─── ADVANCED MANAGE TOGGLE ──────────────────────────────────────
async function onAdvToggle(featureKey, enabled) {
  try {
    const res = await fetch(`${API_BASE}/api/advanced-manage?token=${getToken()}`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ feature_key: featureKey, enabled: enabled }),
    });
    const data = await res.json();
    if (data.success) {
      toast(
        enabled
          ? `✅ เปิดโหมดจัดการขั้นสูง — เมื่อเกิดเหตุจะปิด permission ก่อนทันที`
          : `🔓 ปิดโหมดจัดการขั้นสูง — กลับสู่การตรวจจับปกติ`,
        'success'
      );
    } else {
      toast(`❌ ${data.error || 'เกิดข้อผิดพลาด'}`, 'error');
      // revert toggle
      const cb = document.getElementById('adv-en-' + featureKey);
      if (cb) cb.checked = !enabled;
    }
  } catch (err) {
    toast(`❌ เชื่อมต่อไม่ได้: ${err.message}`, 'error');
    const cb = document.getElementById('adv-en-' + featureKey);
    if (cb) cb.checked = !enabled;
  }
}

function getFeatVal(key) {
  const en        = document.getElementById('feat-en-' + key);
  const limit     = document.getElementById('feat-limit-' + key);
  const windowEl  = document.getElementById('feat-window-' + key);
  const windowUnit= document.getElementById('feat-window-unit-' + key);
  const pwrap     = document.getElementById('punish-' + key);
  const advEn     = document.getElementById('adv-en-' + key);
  const tdurEl    = document.getElementById('feat-timeout-dur-' + key);
  const tdurUnit  = document.getElementById('feat-timeout-unit-' + key);
  const windowSec = windowEl ? toSeconds(windowEl.value, windowUnit?.value||'s') : 10;
  const punishment= pwrap ? (pwrap.dataset.val||'ban') : 'ban';
  const timeoutDur= tdurEl ? toSeconds(tdurEl.value, tdurUnit?.value||'s') : 300;
  return {
    enabled:          en    ? en.checked  : false,
    limit:            limit ? parseInt(limit.value)||3 : 3,
    window:           windowSec,
    punishment:       punishment,
    timeout_duration: punishment === 'timeout' ? timeoutDur : undefined,
    _adv_mode:        advEn ? advEn.checked : false,
  };
}

// ─── RENDER PAGES ─────────────────────────────────────────────────
function renderAllPages(cfg) {
  renderAntiNuke(cfg);
  renderAntiRaid(cfg);
  renderLockdown(cfg);
  renderAntiSpam(cfg);
  renderVoice(cfg);
  setTimeout(() => { if (window.lucide) lucide.createIcons(); }, 50);
}

function renderAntiNuke(cfg) {
  const FEATURES = [
    {key:'anti_ban',         emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="17" y1="8" x2="23" y2="14"/><line x1="23" y1="8" x2="17" y2="14"/></svg>',        name:'Anti-Ban Member',                 desc:'ป้องกันการกดแบนสมาชิกถี่เกินไป'},
    {key:'anti_kick',        emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="22" y1="11" x2="16" y2="11"/></svg>',     name:'Anti-Kick Member',                desc:'ป้องกันการกดเตะสมาชิกถี่เกินไป'},
    {key:'anti_ch_create',   emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/><line x1="12" y1="11" x2="12" y2="17"/><line x1="9" y1="14" x2="15" y2="14"/></svg>',    name:'Anti-Channel Create',             desc:'ป้องกันการสร้างห้องรัวๆ'},
    {key:'anti_ch_delete',   emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/><line x1="9" y1="14" x2="15" y2="14"/></svg>',   name:'Anti-Channel Delete',             desc:'ป้องกันการลบห้องรัวๆ'},
    {key:'anti_ch_update',   emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/><polyline points="16 3 12 7 8 3"/></svg>',    name:'Anti-Channel Update',             desc:'ป้องกันการแก้ไขห้องถี่เกินไป'},
    {key:'anti_role_create', emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2H2v10l9.29 9.29c.94.94 2.48.94 3.42 0l6.58-6.58c.94-.94.94-2.48 0-3.42L12 2Z"/><path d="M7 7h.01"/><line x1="12" y1="12" x2="16" y2="12"/><line x1="14" y1="10" x2="14" y2="14"/></svg>',            name:'Anti-Role Create',                desc:'ป้องกันการสร้างยศรัวๆ'},
    {key:'anti_role_delete', emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2H2v10l9.29 9.29c.94.94 2.48.94 3.42 0l6.58-6.58c.94-.94.94-2.48 0-3.42L12 2Z"/><path d="M7 7h.01"/><line x1="11" y1="12" x2="16" y2="12"/></svg>',       name:'Anti-Role Delete',                desc:'ป้องกันการลบยศรัวๆ'},
    {key:'anti_role_update', emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2H2v10l9.29 9.29c.94.94 2.48.94 3.42 0l6.58-6.58c.94-.94.94-2.48 0-3.42L12 2Z"/><path d="M7 7h.01"/><path d="M20.49 15.49a9 9 0 1 1-2.12-9.36L23 10.5"/><path d="M23 4v6.5h-6.5"/></svg>',     name:'Anti-Role Update',                desc:'ป้องกันการแก้ไขยศถี่เกินไป'},
    {key:'anti_role_give',   emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>', name:'Anti-Role Give (Dangerous Perm)', desc:'ป้องกันการแจกยศที่มีสิทธิ์อันตราย'},
    {key:'anti_webhook_create',emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="5" r="3"/><path d="M6.5 8a2 2 0 0 0-1.905 1.46L2.1 18.5A2 2 0 0 0 4 21h16a2 2 0 0 0 1.925-2.54L19.4 9.46A2 2 0 0 0 17.5 8"/><path d="M8 12a4 4 0 0 1 8 0"/></svg>',      name:'Anti-Webhook Create',             desc:'ป้องกันการสร้าง Webhook แปลกปลอม'},
    {key:'anti_webhook_delete',emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="5" r="3"/><path d="M6.5 8a2 2 0 0 0-1.905 1.46L2.1 18.5A2 2 0 0 0 4 21h16a2 2 0 0 0 1.925-2.54L19.4 9.46A2 2 0 0 0 17.5 8"/><line x1="9" y1="14" x2="15" y2="14"/></svg>',      name:'Anti-Webhook Delete',             desc:'ป้องกันการลบ Webhook รัวๆ'},
    {key:'anti_bot_add',     emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2"/><path d="M20 14h2"/><path d="M15 13v2"/><path d="M9 13v2"/></svg>',            name:'Anti-Bot Add',                   desc:'ตรวจจับและจัดการบอทที่ถูกเชิญโดยไม่ได้รับอนุญาต'},
    {key:'anti_guild_update',emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect width="20" height="8" x="2" y="2" rx="2" ry="2"/><rect width="20" height="8" x="2" y="14" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>',         name:'Anti-Guild Update',               desc:'ป้องกันการเปลี่ยนชื่อ/ไอคอนเซิร์ฟเวอร์'},
    {key:'anti_vanity',      emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 17H7A5 5 0 0 1 7 7h2"/><path d="M15 7h2a5 5 0 1 1 0 10h-2"/><line x1="8" y1="12" x2="16" y2="12"/></svg>',         name:'Anti-Vanity URL',                desc:'ป้องกันการเปลี่ยน/ลบ Vanity URL (ดึงกลับทันที)'},
    {key:'anti_prune',       emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="6" cy="6" r="3"/><path d="M8.12 8.12 12 12"/><path d="M20 4 8.12 15.88"/><circle cx="18" cy="18" r="3"/><path d="M11.88 11.88 16 16"/></svg>',       name:'Anti-Prune Members',              desc:'ป้องกันการ Prune สมาชิกกะทันหัน'},
    {key:'anti_integration', emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22V12"/><path d="m17 7-5-5-5 5"/><path d="M17 22H7a2 2 0 0 1-2-2v-2a2 2 0 0 1 2-2h10a2 2 0 0 1 2 2v2a2 2 0 0 1-2 2z"/></svg>',           name:'Anti-Integration Create/Update',  desc:'ป้องกันการเชื่อมต่อแอปภายนอกที่น่าสงสัย'},
  ];
  const grid = document.getElementById('grid-antinuke');
  grid.innerHTML = FEATURES.map(f => buildFeatureCard(f.key, f.emoji, f.name, f.desc, cfg)).join('');
}

function renderAntiRaid(cfg) {
  const grid = document.getElementById('grid-antiraid');

  // Anti-Join Flood — standard card
  const floodHtml = buildFeatureCard('anti_join_flood', '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M2 6c.6.5 1.2 1 2.5 1C7 7 7 5 9.5 5c2.6 0 2.4 2 5 2 2.5 0 2.5-2 5-2 1.3 0 1.9.5 2.5 1"/><path d="M2 12c.6.5 1.2 1 2.5 1 2.5 0 2.5-2 5-2 2.6 0 2.4 2 5 2 2.5 0 2.5-2 5-2 1.3 0 1.9.5 2.5 1"/><path d="M2 18c.6.5 1.2 1 2.5 1 2.5 0 2.5-2 5-2 2.6 0 2.4 2 5 2 2.5 0 2.5-2 5-2 1.3 0 1.9.5 2.5 1"/></svg>',
    'Anti-Join Flood (Mass Join)',
    'ตรวจจับบัญชีจำนวนมากเข้าร่วมพร้อมกัน', cfg);

  // Anti-Account Age — Threshold = min days, Window ไม่มีความหมาย → ซ่อน window
  const ageFeat   = cfg['anti_account_age'] || {};
  const agePunish = ageFeat.punishment || 'kick';
  const ageOpts   = PUNISHMENTS.map(p =>
    `<div class="punish-btn ${p.cls} ${agePunish===p.val?'sel':''}"
       onclick="selectFeatPunish('anti_account_age',this,'${p.val}','${p.cls}')">
       <div class="punish-ic">${p.ic}</div>${p.label}
     </div>`).join('');
  const ageHtml = `
  <div class="feat-card ${ageFeat.enabled?'enabled':''}" id="fcard-anti_account_age">
    <div class="feat-header">
      <div class="feat-emoji"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 7.5V6a2 2 0 0 0-2-2H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h3.5"/><path d="M16 2v4"/><path d="M8 2v4"/><path d="M3 10h5"/><circle cx="18" cy="18" r="4"/><path d="M18 16.5V18l1 1"/></svg></div>
      <div class="feat-label">
        <div class="feat-name">Anti-Account Age (Alt Detector)</div>
        <div class="feat-desc">ดีดออกทันทีหากบัญชีอายุน้อยกว่าที่กำหนด</div>
      </div>
      <label class="tog">
        <input type="checkbox" id="feat-en-anti_account_age" ${ageFeat.enabled?'checked':''}
               onchange="toggleFeatCard('anti_account_age',this.checked)">
        <span class="tog-sl"></span>
      </label>
    </div>
    <div class="feat-body">
      <div class="sub-field">
        <div class="sub-label">บทลงโทษ</div>
        <div class="punish-wrap" id="punish-anti_account_age" data-val="${agePunish}">${ageOpts}</div>
      </div>
      <div class="sub-field">
        <div class="sub-label">อายุบัญชีขั้นต่ำ (วัน)</div>
        <div class="sub-row">
          <input class="sub-input" type="number" id="feat-limit-anti_account_age"
                 min="1" max="365" value="${ageFeat.limit ?? 7}">
          <span class="sub-unit">วัน</span>
        </div>
      </div>
    </div>
  </div>`;

  // Anti-Default Avatar — ไม่ต้องการ Threshold / Window
  const avFeat   = cfg['anti_no_avatar'] || {};
  const avPunish = avFeat.punishment || 'kick';
  const avOpts   = PUNISHMENTS.map(p =>
    `<div class="punish-btn ${p.cls} ${avPunish===p.val?'sel':''}"
       onclick="selectFeatPunish('anti_no_avatar',this,'${p.val}','${p.cls}')">
       <div class="punish-ic">${p.ic}</div>${p.label}
     </div>`).join('');
  const avHtml = `
  <div class="feat-card ${avFeat.enabled?'enabled':''}" id="fcard-anti_no_avatar">
    <div class="feat-header">
      <div class="feat-emoji"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="10" r="3"/><path d="M7 20.662V19a2 2 0 0 1 2-2h6a2 2 0 0 1 2 2v1.662"/></svg></div>
      <div class="feat-label">
        <div class="feat-name">Anti-Default Avatar Join</div>
        <div class="feat-desc">คัดกรองบัญชีที่ไม่มีรูปโปรไฟล์ (รูปดีฟอลต์ Discord)</div>
      </div>
      <label class="tog">
        <input type="checkbox" id="feat-en-anti_no_avatar" ${avFeat.enabled?'checked':''}
               onchange="toggleFeatCard('anti_no_avatar',this.checked)">
        <span class="tog-sl"></span>
      </label>
    </div>
    <div class="feat-body">
      <div class="sub-field">
        <div class="sub-label">บทลงโทษ</div>
        <div class="punish-wrap" id="punish-anti_no_avatar" data-val="${avPunish}">${avOpts}</div>
      </div>
    </div>
  </div>`;

  grid.innerHTML = floodHtml + ageHtml + avHtml;
}

function renderLockdown(cfg) {
  const ld = cfg['server_lockdown'] || {};
  const grid = document.getElementById('grid-lockdown');
  grid.innerHTML = `
  <div class="feat-card ${ld.enabled?'enabled':''}" id="fcard-server_lockdown">
    <div class="feat-header">
      <div class="feat-emoji"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg></div>
      <div class="feat-label">
        <div class="feat-name">Server Lockdown Protocol</div>
        <div class="feat-desc">ปิดการพิมพ์ทุกห้องและยกเลิกลิงก์เชิญทันที</div>
      </div>
      <label class="tog">
        <input type="checkbox" id="feat-en-server_lockdown" ${ld.enabled?'checked':''}
               onchange="toggleFeatCard('server_lockdown',this.checked)">
        <span class="tog-sl"></span>
      </label>
    </div>
    <div class="feat-body">
      <div style="font-size:12px;color:var(--warn);background:var(--warn-dim);border:1px solid rgba(255,165,2,.2);border-radius:8px;padding:10px 12px;">
        เปิดสวิตช์นี้จะล็อกทุกห้องทันที กด "บันทึก" เพื่อยืนยัน
      </div>
      <button class="btn btn-danger btn-full" onclick="toggleLockdown(true)"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> เปิด Lockdown ทันที</button>
      <button class="btn btn-success btn-full" onclick="toggleLockdown(false)"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect width="18" height="11" x="3" y="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 9.9-1"/></svg> ปิด Lockdown ทันที</button>
    </div>
  </div>`;
}

function renderAntiSpam(cfg) {
  const FEATURES = [
    {key:'anti_mass_mentions', emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M16 8v5a3 3 0 0 0 6 0v-1a10 10 0 1 0-3.92 7.94"/></svg>', name:'Anti-Mass Mentions',
     desc:'ตรวจจับการแท็กสมาชิกจำนวนมากในข้อความเดียว (@everyone / @here / แท็กรายคน)'},
    {key:'anti_text_spam',     emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m17 2 4 4-4 4"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><path d="m7 22-4-4 4-4"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/></svg>', name:'Anti-Text Spam',
     desc:'ตรวจจับการส่งข้อความซ้ำๆ ถี่ๆ'},
    {key:'anti_link_spam',     emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 17H7A5 5 0 0 1 7 7h2"/><path d="M15 7h2a5 5 0 1 1 0 10h-2"/><line x1="8" y1="12" x2="16" y2="12"/></svg>', name:'Anti-Link & Invite Spam',
     desc:'ตรวจจับการส่งลิงก์เชิญหรือ URL อันตราย'},
    {key:'anti_att_spam',      emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m21.44 11.05-9.19 9.19a6 6 0 0 1-8.49-8.49l8.57-8.57A4 4 0 1 1 18 8.84l-8.59 8.57a2 2 0 0 1-2.83-2.83l8.49-8.48"/></svg>', name:'Anti-Attachment/Media Spam',
     desc:'ตรวจจับการส่งไฟล์ ภาพ หรือสติกเกอร์รัวๆ'},
    {key:'anti_emoji_spam',    emoji:'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/></svg>', name:'Anti-Emoji/Reaction Spam',
     desc:'ตรวจจับการกดรีแอคชั่นหรือส่ง emoji รัวๆ'},
  ];
  const grid = document.getElementById('grid-antispam');
  grid.innerHTML = FEATURES.map(f => buildFeatureCard(f.key, f.emoji, f.name, f.desc, cfg)).join('');
}

function renderVoice(cfg) {
  const feat = cfg['voiceabuse'] || {};
  const punish = feat.punishment || 'timeout';
  // [Session 6] คำนวณ window display + unit สำหรับ voiceabuse (เหมือน buildFeatureCard)
  const vaSec = feat.window ?? 10;
  let vaWinDisplay, vaWinUnit;
  if (vaSec % 3600 === 0 && vaSec >= 3600) { vaWinDisplay = vaSec/3600; vaWinUnit = 'h'; }
  else if (vaSec % 60 === 0 && vaSec >= 60) { vaWinDisplay = vaSec/60;   vaWinUnit = 'm'; }
  else { vaWinDisplay = vaSec; vaWinUnit = 's'; }
  const punishOpts = PUNISHMENTS.map(p =>
    `<div class="punish-btn ${p.cls} ${punish===p.val?'sel':''}"
       onclick="selectFeatPunish('voiceabuse',this,'${p.val}','${p.cls}')">
       <div class="punish-ic">${p.ic}</div>${p.label}
     </div>`).join('');
  document.getElementById('grid-voice').innerHTML = `
  <div class="feat-card ${feat.enabled?'enabled':''}" id="fcard-voiceabuse">
    <div class="feat-header">
      <div class="feat-emoji"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2a3 3 0 0 0-3 3v7a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3Z"/><path d="M19 10v2a7 7 0 0 1-14 0v-2"/><line x1="12" y1="19" x2="12" y2="22"/></svg></div>
      <div class="feat-label">
        <div class="feat-name">Voice Abuse Detection</div>
        <div class="feat-desc">ตรวจจับการ mute/move/disconnect สมาชิกใน Voice Channel รัวๆ</div>
      </div>
      <label class="tog">
        <input type="checkbox" id="feat-en-voiceabuse" ${feat.enabled?'checked':''}
               onchange="toggleFeatCard('voiceabuse',this.checked)">
        <span class="tog-sl"></span>
      </label>
    </div>
    <div class="feat-body">
      <div class="sub-field">
        <div class="sub-label">บทลงโทษ</div>
        <div class="punish-wrap" id="punish-voiceabuse" data-val="${punish}">${punishOpts}</div>
      </div>
      <div class="sub-field">
        <div class="sub-label">จำนวนครั้งสูงสุด (Limit)</div>
        <div class="sub-row">
          <input class="sub-input" type="number" id="feat-limit-voiceabuse" min="1" max="100" value="${feat.limit||5}">
          <span class="sub-unit">ครั้ง</span>
        </div>
      </div>
      <div class="sub-field">
        <div class="sub-label">ช่วงเวลา (Window)</div>
        <div class="sub-row">
          <input class="sub-input" type="number" id="feat-window-voiceabuse" min="1" max="86400" value="${vaWinDisplay}">
          <select class="sub-select" id="va-window-unit">
            <option value="s" ${vaWinUnit==='s'?'selected':''}>วินาที</option>
            <option value="m" ${vaWinUnit==='m'?'selected':''}>นาที</option>
            <option value="h" ${vaWinUnit==='h'?'selected':''}>ชั่วโมง</option>
          </select>
        </div>
      </div>
      <div class="sub-field">
        <div class="sub-label">⏱ ระยะเวลา Timeout (นาที)</div>
        <div class="sub-row">
          <input class="sub-input" type="number" id="va-mute-dur" min="1" max="43200" value="${feat.mute_duration||10}">
          <span class="sub-unit">นาที</span>
        </div>
      </div>
    </div>
  </div>`;
}

function renderHomeStatus(cfg) {
  // กลุ่ม 1: Anti-Nuke (16 features)
  const NUKE = [
    {key:'anti_ban',          icon:'user-x',     name:'Anti-Ban Member'},
    {key:'anti_kick',         icon:'user-minus',  name:'Anti-Kick Member'},
    {key:'anti_ch_create',    icon:'folder-plus', name:'Anti-Channel Create'},
    {key:'anti_ch_delete',    icon:'folder-minus',name:'Anti-Channel Delete'},
    {key:'anti_ch_update',    icon:'folder-edit', name:'Anti-Channel Update'},
    {key:'anti_role_create',  icon:'tag',         name:'Anti-Role Create'},
    {key:'anti_role_delete',  icon:'x-circle',    name:'Anti-Role Delete'},
    {key:'anti_role_update',  icon:'refresh-cw',  name:'Anti-Role Update'},
    {key:'anti_role_give',    icon:'alert-triangle', name:'Anti-Role Give (Dangerous)'},
    {key:'anti_webhook_create',icon:'webhook',    name:'Anti-Webhook Create'},
    {key:'anti_webhook_delete',icon:'webhook',    name:'Anti-Webhook Delete'},
    {key:'anti_bot_add',      icon:'bot',         name:'Anti-Bot Add'},
    {key:'anti_guild_update', icon:'server',      name:'Anti-Guild Update'},
    {key:'anti_vanity',       icon:'link-2',      name:'Anti-Vanity URL'},
    {key:'anti_prune',        icon:'scissors',    name:'Anti-Prune Members'},
    {key:'anti_integration',  icon:'plug',        name:'Anti-Integration'},
  ];
  // กลุ่ม 2: Anti-Raid (4 features)
  const RAID = [
    {key:'anti_join_flood',  icon:'waves',           name:'Anti-Join Flood'},
    {key:'anti_account_age', icon:'calendar-clock',  name:'Anti-Account Age'},
    {key:'anti_no_avatar',   icon:'user-circle-2',   name:'Anti-Default Avatar'},
    {key:'server_lockdown',  icon:'lock',            name:'Server Lockdown'},
  ];
  // กลุ่ม 3: Anti-Spam (5 features)
  const SPAM = [
    {key:'anti_mass_mentions', icon:'at-sign',   name:'Anti-Mass Mentions'},
    {key:'anti_text_spam',     icon:'repeat-2',  name:'Anti-Text Spam'},
    {key:'anti_link_spam',     icon:'link-2',    name:'Anti-Link & Invite Spam'},
    {key:'anti_att_spam',      icon:'paperclip', name:'Anti-Attachment/Media Spam'},
    {key:'anti_emoji_spam',    icon:'smile',     name:'Anti-Emoji/Reaction Spam'},
  ];
  // Extras
  const EXTRA = [
    {key:'automod',     icon:'bot', name:'Auto Mod'},
    {key:'voiceabuse',  icon:'mic', name:'Voice Abuse'},
  ];

  function countOn(arr) { return arr.filter(s => (cfg[s.key]||{}).enabled).length; }

  // ── Category Summary Cards ──
  const catIcons = {
    nuke: '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
    raid: '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>',
    spam: '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>',
    general: '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.07 4.93l-1.41 1.41M4.93 4.93l1.41 1.41M19.07 19.07l-1.41-1.41M4.93 19.07l1.41-1.41M12 2v2M12 20v2M2 12h2M20 12h2"/></svg>',
  };
  const cats = [
    { label:'Anti-Nuke', icon: catIcons.nuke, cls:'nuke', arr:NUKE, page:'antinuke', desc:'ป้องกันผู้ดูแลใช้อำนาจในทางที่ผิด' },
    { label:'Anti-Raid',  icon: catIcons.raid, cls:'raid', arr:RAID, page:'antiraid', desc:'สกัดกั้นการโจมตีพร้อมกัน' },
    { label:'Anti-Spam',  icon: catIcons.spam, cls:'spam', arr:SPAM, page:'antispam', desc:'กรองสแปมข้อความและ Mention' },
    { label:'ทั่วไป',     icon: catIcons.general, cls:'general', arr:EXTRA, page:'automod', desc:'Auto Mod, Voice Abuse และอื่นๆ' },
  ];
  const catWrap = document.getElementById('category-cards');
  if (catWrap) {
    catWrap.innerHTML = cats.map(c => {
      const on = countOn(c.arr);
      const total = c.arr.length;
      const pct = total ? Math.round(on / total * 100) : 0;
      return `<div class="cat-card" onclick="goPage('${c.page}')">
        <div class="cat-card-head">
          <div class="cat-card-ic ${c.cls}">${c.icon}</div>
          <div>
            <div class="cat-card-name">${c.label}</div>
            <div class="cat-card-desc">${c.desc}</div>
          </div>
        </div>
        <div class="cat-card-bar"><div class="cat-card-bar-fill ${c.cls}" style="width:${pct}%"></div></div>
        <div class="cat-card-footer">
          <span>เปิดอยู่ <span class="cat-active-count ${c.cls}">${on}/${total}</span></span>
          <span style="color:var(--primary-light);font-size:11px;">ดูรายละเอียด →</span>
        </div>
      </div>`;
    }).join('');
  }

  // ── Detailed Status List (collapsible by group) ──
  function rows(arr) {
    return arr.map(s => {
      const on = (cfg[s.key]||{}).enabled;
      return `<div class="trow">
        <div class="trow-ic"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-${s.icon}"></svg></div>
        <div class="trow-info"><div class="trow-label">${s.name}</div></div>
        <span class="badge ${on?'badge-green':'badge-gray'}">${on?'เปิด':'ปิด'}</span>
      </div>`;
    }).join('');
  }

  document.getElementById('system-status-list').innerHTML = `
    <div style="font-size:10px;font-weight:700;color:var(--danger);text-transform:uppercase;letter-spacing:.8px;padding:6px 0 4px;display:flex;align-items:center;gap:5px;"><svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg> Anti-Nuke (${countOn(NUKE)}/${NUKE.length} เปิด)</div>
    ${rows(NUKE)}
    <div style="font-size:10px;font-weight:700;color:var(--warn);text-transform:uppercase;letter-spacing:.8px;padding:14px 0 4px;display:flex;align-items:center;gap:5px;"><svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M11 3a1 1 0 1 0 2 0 1 1 0 0 0-2 0"/><path d="M11 21a1 1 0 1 0 2 0 1 1 0 0 0-2 0"/><path d="M3 11a1 1 0 1 0 0 2 1 1 0 0 0 0-2"/><path d="M21 11a1 1 0 1 0 0 2 1 1 0 0 0 0-2"/><circle cx="12" cy="12" r="9"/></svg> Anti-Raid & Gatekeeper (${countOn(RAID)}/${RAID.length} เปิด)</div>
    ${rows(RAID)}
    <div style="font-size:10px;font-weight:700;color:var(--primary-light);text-transform:uppercase;letter-spacing:.8px;padding:14px 0 4px;display:flex;align-items:center;gap:5px;"><svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><line x1="12" y1="7" x2="12" y2="11"/><line x1="12" y1="15" x2="12.01" y2="15"/></svg> Anti-Spam (${countOn(SPAM)}/${SPAM.length} เปิด)</div>
    ${rows(SPAM)}
    <div style="font-size:10px;font-weight:700;color:var(--success);text-transform:uppercase;letter-spacing:.8px;padding:14px 0 4px;display:flex;align-items:center;gap:5px;"><svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg> ทั่วไป (${countOn(EXTRA)}/${EXTRA.length} เปิด)</div>
    ${rows(EXTRA)}
  `;
  if (window.lucide) lucide.createIcons();
}

// ─── LOG CHANNELS ─────────────────────────────────────────────────
const LOG_CH_TYPES = [
  // ── ห้องเดิม 10 ──
  {key:'member_join',       label:'สมาชิกเข้าร่วม',        icon:'user-plus'},
  {key:'member_leave',      label:'สมาชิกออกจาก',          icon:'user-minus'},
  {key:'member_ban',        label:'แบนสมาชิก',             icon:'ban'},
  {key:'member_kick',       label:'เตะสมาชิก',             icon:'user-x'},
  {key:'message_delete',    label:'ลบข้อความ',             icon:'trash-2'},
  {key:'message_edit',      label:'แก้ไขข้อความ',          icon:'pencil'},
  {key:'role_update',       label:'เปลี่ยนยศ',             icon:'tag'},
  {key:'channel_update',    label:'เปลี่ยนห้อง',           icon:'hash'},
  {key:'voice_update',      label:'Voice',                 icon:'mic'},
  {key:'invite_create',     label:'สร้างลิงก์เชิญ',        icon:'link'},
  // ── ห้องใหม่ 30 ──
  {key:'member_timeout',    label:'ไทม์เอาต์สมาชิก',       icon:'timer'},
  {key:'member_unban',      label:'ยกเลิกแบน',             icon:'shield-off'},
  {key:'member_nickname',   label:'เปลี่ยนชื่อเล่น',       icon:'pencil-line'},
  {key:'member_role_add',   label:'ให้ยศสมาชิก',           icon:'user-check'},
  {key:'member_role_remove',label:'ถอนยศสมาชิก',           icon:'user-minus-2'},
  {key:'member_quarantine', label:'กักกันสมาชิก',           icon:'lock'},
  {key:'channel_create',    label:'สร้างห้อง',             icon:'folder-plus'},
  {key:'channel_delete',    label:'ลบห้อง',                icon:'folder-x'},
  {key:'channel_permission',label:'แก้ไขสิทธิ์ห้อง',       icon:'shield'},
  {key:'role_create',       label:'สร้างยศ',               icon:'badge-plus'},
  {key:'role_delete',       label:'ลบยศ',                  icon:'badge-x'},
  {key:'role_permission',   label:'แก้ไขสิทธิ์ยศ',         icon:'settings-2'},
  {key:'webhook_create',    label:'สร้าง Webhook',          icon:'webhook'},
  {key:'webhook_delete',    label:'ลบ Webhook',            icon:'unplug'},
  {key:'emoji_create',      label:'สร้าง Emoji',           icon:'smile-plus'},
  {key:'emoji_delete',      label:'ลบ Emoji',              icon:'smile-x'},
  {key:'sticker_create',    label:'สร้าง Sticker',         icon:'sticker'},
  {key:'sticker_delete',    label:'ลบ Sticker',            icon:'square-x'},
  {key:'thread_create',     label:'สร้าง Thread',          icon:'message-square-plus'},
  {key:'thread_delete',     label:'ลบ Thread',             icon:'message-square-x'},
  {key:'thread_update',     label:'แก้ไข Thread',          icon:'message-square-dot'},
  {key:'voice_join',        label:'เข้า Voice',            icon:'volume-2'},
  {key:'voice_leave',       label:'ออก Voice',             icon:'volume-x'},
  {key:'voice_move',        label:'ย้ายห้อง Voice',        icon:'arrow-left-right'},
  {key:'voice_mute',        label:'มิวต์/ดีเอฟ Voice',     icon:'mic-off'},
  {key:'invite_delete',     label:'ลบลิงก์เชิญ',           icon:'link-2-off'},
  {key:'server_update',     label:'แก้ไขเซิร์ฟเวอร์',      icon:'server'},
  {key:'automod_action',    label:'AutoMod Action',         icon:'bot'},
  {key:'spam_detect',       label:'ตรวจพบสแปม',            icon:'alert-triangle'},
  {key:'raid_detect',       label:'ตรวจพบ Raid',           icon:'siren'},
  {key:'bot_added',         label:'บอทถูกเพิ่ม',           icon:'cpu'},
];

// รายการพิเศษที่มี API endpoint แยก (ไม่ใช้ /api/log-channels/create)
const SPECIAL_CH_TYPES = [
  {
    key:     'bot_action_log',
    label:   'Bot Action Log',
    icon:    'bot',
    desc:    'บันทึกทุก action ของบอท (ban/kick/timeout/quarantine) พร้อม timestamp',
    createUrl: '/api/bot-action-log/create',
    deleteUrl: '/api/bot-action-log/delete',
  },
  {
    key:     'honeypot',
    label:   'Honeypot (ห้องหลอก)',
    icon:    'flask-conical',
    desc:    'ห้องล่อ — ใครส่งข้อความเข้ามาจะถูกแจ้งเตือนทันที (ไม่มีบทลงโทษ)',
    createUrl: '/api/honeypot/create',
    deleteUrl: '/api/honeypot/delete',
  },
];

function renderLogChannels() {
  const grid = document.getElementById('logch-grid');
  if (!grid) return;
  const LOGCH_ICONS = {
    'user-plus':  '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="19" y1="8" x2="19" y2="14"/><line x1="22" y1="11" x2="16" y2="11"/></svg>',
    'user-minus': '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="22" y1="11" x2="16" y2="11"/></svg>',
    'ban':        '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>',
    'user-x':     '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="17" y1="8" x2="23" y2="14"/><line x1="23" y1="8" x2="17" y2="14"/></svg>',
    'trash-2':    '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>',
    'pencil':     '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M17 3a2.85 2.83 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z"/></svg>',
    'tag':        '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2H2v10l9.29 9.29c.94.94 2.48.94 3.42 0l6.58-6.58c.94-.94.94-2.48 0-3.42L12 2Z"/><path d="M7 7h.01"/></svg>',
    'hash':       '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><line x1="4" y1="9" x2="20" y2="9"/><line x1="4" y1="15" x2="20" y2="15"/><line x1="10" y1="3" x2="8" y2="21"/><line x1="16" y1="3" x2="14" y2="21"/></svg>',
    'mic':        '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2a3 3 0 0 0-3 3v7a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3Z"/><path d="M19 10v2a7 7 0 0 1-14 0v-2"/><line x1="12" y1="19" x2="12" y2="22"/></svg>',
    'link':       '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>',
    'bot':        '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 8V4H8"/><rect width="16" height="12" x="4" y="8" rx="2"/><path d="M2 14h2"/><path d="M20 14h2"/><path d="M15 13v2"/><path d="M9 13v2"/></svg>',
    'flask-conical':'<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M14 2v6l3.22 4.83A4 4 0 0 1 13.83 19H10.17a4 4 0 0 1-3.39-6.17L10 8V2"/><path d="M8.5 2h7"/><path d="M7 16h10"/></svg>',
    // ── icons ใหม่ ──
    'timer':           '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><line x1="10" y1="2" x2="14" y2="2"/><line x1="12" y1="14" x2="12" y2="8"/><circle cx="12" cy="14" r="8"/></svg>',
    'shield-off':      '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M19.69 14a6.9 6.9 0 0 0 .31-2V5l-8-3-3.16 1.18"/><path d="M4.73 4.73 4 5v7c0 6 8 10 8 10a20.29 20.29 0 0 0 5.62-4.38"/><line x1="2" y1="2" x2="22" y2="22"/></svg>',
    'pencil-line':     '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.376 3.622a1 1 0 0 1 3.002 3.002L7.368 18.635a2 2 0 0 1-.855.506l-2.872.838a.5.5 0 0 1-.62-.62l.838-2.872a2 2 0 0 1 .506-.854z"/></svg>',
    'user-check':      '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><polyline points="16 11 18 13 22 9"/></svg>',
    'user-minus-2':    '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><line x1="22" y1="11" x2="16" y2="11"/></svg>',
    'lock':            '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>',
    'folder-plus':     '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/><line x1="12" y1="11" x2="12" y2="17"/><line x1="9" y1="14" x2="15" y2="14"/></svg>',
    'folder-x':        '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/><line x1="9.5" y1="11.5" x2="14.5" y2="16.5"/><line x1="14.5" y1="11.5" x2="9.5" y2="16.5"/></svg>',
    'shield':          '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>',
    'badge-plus':      '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3.85 8.62a4 4 0 0 1 4.78-4.77 4 4 0 0 1 6.74 0 4 4 0 0 1 4.78 4.78 4 4 0 0 1 0 6.74 4 4 0 0 1-4.77 4.78 4 4 0 0 1-6.75 0 4 4 0 0 1-4.78-4.77 4 4 0 0 1 0-6.76Z"/><line x1="12" y1="8" x2="12" y2="16"/><line x1="8" y1="12" x2="16" y2="12"/></svg>',
    'badge-x':         '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3.85 8.62a4 4 0 0 1 4.78-4.77 4 4 0 0 1 6.74 0 4 4 0 0 1 4.78 4.78 4 4 0 0 1 0 6.74 4 4 0 0 1-4.77 4.78 4 4 0 0 1-6.75 0 4 4 0 0 1-4.78-4.77 4 4 0 0 1 0-6.76Z"/><line x1="9" y1="9" x2="15" y2="15"/><line x1="15" y1="9" x2="9" y2="15"/></svg>',
    'settings-2':      '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 7H9"/><path d="M14 17H3"/><circle cx="17" cy="17" r="3"/><circle cx="7" cy="7" r="3"/></svg>',
    'webhook':         '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M18 16.98h-5.99c-1.1 0-1.95.94-2.48 1.9A4 4 0 0 1 2 17c.01-.7.2-1.4.57-2"/><path d="m6 17 3.13-5.78c.53-.97.1-2.18-.5-3.1a4 4 0 1 1 6.89-4.06"/><path d="m12 6 3.13 5.73C15.66 12.7 16.9 13 18 13a4 4 0 0 1 0 8"/></svg>',
    'unplug':          '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m19 5 3-3"/><path d="m2 22 3-3"/><path d="M6.3 20.3a2.4 2.4 0 0 0 3.4 0L12 18l-6-6-2.3 2.3a2.4 2.4 0 0 0 0 3.4Z"/><path d="M17.7 3.7a2.4 2.4 0 0 0-3.4 0L12 6l6 6 2.3-2.3a2.4 2.4 0 0 0 0-3.4Z"/><path d="m14 6-2 2"/><path d="m9 15 2-2"/><path d="m10 6-5 5"/><path d="m14 18 5-5"/></svg>',
    'smile-plus':      '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M22 11v1a10 10 0 1 1-9-10"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/><path d="M16 5h6"/><path d="M19 2v6"/></svg>',
    'smile-x':         '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20.27 9.73A10 10 0 1 0 21 12.6"/><path d="M8 14s1.5 2 4 2 4-2 4-2"/><line x1="9" y1="9" x2="9.01" y2="9"/><line x1="15" y1="9" x2="15.01" y2="9"/><line x1="22" y1="2" x2="18" y2="6"/><line x1="18" y1="2" x2="22" y2="6"/></svg>',
    'sticker':         '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M15.5 3H5a2 2 0 0 0-2 2v14c0 1.1.9 2 2 2h14a2 2 0 0 0 2-2V8.5L15.5 3Z"/><path d="M15 3v6h6"/><path d="M10 11h.01"/><path d="M14 11h.01"/><path d="M10 15a3.5 3.5 0 0 0 4 0"/></svg>',
    'square-x':        '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"/><line x1="9" y1="9" x2="15" y2="15"/><line x1="15" y1="9" x2="9" y2="15"/></svg>',
    'message-square-plus': '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><line x1="12" y1="7" x2="12" y2="13"/><line x1="9" y1="10" x2="15" y2="10"/></svg>',
    'message-square-x':    '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><line x1="9" y1="8" x2="15" y2="14"/><line x1="15" y1="8" x2="9" y2="14"/></svg>',
    'message-square-dot':  '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/><path d="M12 11h.01"/></svg>',
    'volume-2':        '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><path d="M15.54 8.46a5 5 0 0 1 0 7.07"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14"/></svg>',
    'volume-x':        '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"/><line x1="23" y1="9" x2="17" y2="15"/><line x1="17" y1="9" x2="23" y2="15"/></svg>',
    'arrow-left-right':'<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M8 3 4 7l4 4"/><path d="M4 7h16"/><path d="m16 21 4-4-4-4"/><path d="M20 17H4"/></svg>',
    'mic-off':         '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><line x1="2" y1="2" x2="22" y2="22"/><path d="M18.89 13.23A7.12 7.12 0 0 0 19 12v-2"/><path d="M5 10v2a7 7 0 0 0 12 5"/><path d="M15 9.34V5a3 3 0 0 0-5.68-1.33"/><path d="M9 9v3a3 3 0 0 0 5.12 2.12"/><line x1="12" y1="19" x2="12" y2="22"/></svg>',
    'link-2-off':      '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M9 17H7A5 5 0 0 1 7 7"/><path d="M15 7h2a5 5 0 0 1 4 8"/><line x1="8" y1="12" x2="12" y2="12"/><line x1="2" y1="2" x2="22" y2="22"/></svg>',
    'server':          '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="20" height="8" rx="2" ry="2"/><rect x="2" y="14" width="20" height="8" rx="2" ry="2"/><line x1="6" y1="6" x2="6.01" y2="6"/><line x1="6" y1="18" x2="6.01" y2="18"/></svg>',
    'alert-triangle':  '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    'siren':           '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M7 18H4a1 1 0 0 1-1-1v-1a4 4 0 0 1 4-4h10a4 4 0 0 1 4 4v1a1 1 0 0 1-1 1h-3"/><path d="M12 6V3"/><path d="m4.93 10.93 1.41-1.41"/><path d="M19.07 10.93 17.66 9.52"/><path d="M7 18a5 5 0 0 1 10 0"/></svg>',
    'cpu':             '<svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/><line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/><line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/></svg>',
  };

  // ── ห้อง log ปกติ ──
  const normalHtml = LOG_CH_TYPES.map(t => {
    const chId = logChConfig[t.key];
    const has = !!chId;
    const iconSvg = LOGCH_ICONS[t.icon] || '';
    return `<div class="logch-card">
      <div class="logch-left">
        <div class="logch-ic">${iconSvg}</div>
        <div>
          <div class="logch-name">${t.label}</div>
          <div class="logch-st ${has?'has':'none'}">${has?`ID: ${chId}`:'ยังไม่มีห้อง'}</div>
        </div>
      </div>
      <div>${has
        ? `<button class="btn btn-danger btn-sm" onclick="deleteLogChannel('${t.key}')">ลบ</button>`
        : `<button class="btn btn-success btn-sm" onclick="createLogChannel('${t.key}')">+ สร้าง</button>`
      }</div>
    </div>`;
  }).join('');

  // ── ห้องพิเศษ (bot-action-log + honeypot) ──
  const specialHtml = SPECIAL_CH_TYPES.map(t => {
    const chId = logChConfig[t.key];
    const has = !!chId;
    const iconSvg = LOGCH_ICONS[t.icon] || '';
    return `<div class="logch-card" style="grid-column:span 2;border-color:${has?'rgba(0,200,150,.3)':'var(--border)'};">
      <div class="logch-left" style="flex:1;">
        <div class="logch-ic" style="${has?'background:rgba(0,200,150,.12);color:var(--success);':''}">${iconSvg}</div>
        <div>
          <div class="logch-name">${t.label}</div>
          <div style="font-size:10.5px;color:var(--muted);margin-top:2px;">${t.desc}</div>
          <div class="logch-st ${has?'has':'none'}" style="margin-top:3px;">${has?`✅ ห้องพร้อม — ID: ${chId}`:'ยังไม่มีห้อง'}</div>
        </div>
      </div>
      <div>${has
        ? `<button class="btn btn-danger btn-sm" onclick="deleteSpecialChannel('${t.key}','${t.deleteUrl}')">ถอดออก</button>`
        : `<button class="btn btn-success btn-sm" onclick="createSpecialChannel('${t.key}','${t.createUrl}')">+ สร้าง</button>`
      }</div>
    </div>`;
  }).join('');

  grid.innerHTML = normalHtml + `<div style="grid-column:span 2;margin-top:8px;font-size:10px;font-weight:700;color:var(--muted2);text-transform:uppercase;letter-spacing:.6px;">ห้องระบบพิเศษ</div>` + specialHtml;
  if (window.lucide) lucide.createIcons();
}

async function createLogChannel(logType) {
  try {
    const r = await fetch(`${API_BASE}/api/log-channels/create?token=${encodeURIComponent(getToken())}`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({log_type: logType})
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error);
    logChConfig[logType] = d.channel_id;
    renderLogChannels();
    toast(`สร้างห้อง ${d.channel_name} แล้ว`, 'success');
  } catch(e) { toast(`เกิดข้อผิดพลาด: ${e.message}`, 'error'); }
}

async function deleteLogChannel(logType) {
  try {
    await fetch(`${API_BASE}/api/log-channels/delete?token=${encodeURIComponent(getToken())}`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({log_type: logType})
    });
    logChConfig[logType] = null;
    renderLogChannels();
    toast('ลบการเชื่อม log แล้ว', 'success');
  } catch { toast('เกิดข้อผิดพลาด', 'error'); }
}

async function autoCreateLogs() {
  for (const t of LOG_CH_TYPES) {
    if (!logChConfig[t.key]) {
      await createLogChannel(t.key);
      await new Promise(r => setTimeout(r, 600));
    }
  }
}

async function createSpecialChannel(key, url) {
  try {
    const r = await fetch(`${API_BASE}${url}?token=${encodeURIComponent(getToken())}`, {
      method:'POST', headers:{'Content-Type':'application/json'}, body:'{}'
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error);
    logChConfig[key] = d.channel_id;
    renderLogChannels();
    toast(`✅ สร้างห้อง ${d.channel_name} แล้ว`, 'success');
  } catch(e) { toast(`❌ เกิดข้อผิดพลาด: ${e.message}`, 'error'); }
}

async function deleteSpecialChannel(key, url) {
  try {
    await fetch(`${API_BASE}${url}?token=${encodeURIComponent(getToken())}`, {
      method:'POST', headers:{'Content-Type':'application/json'}, body:'{}'
    });
    logChConfig[key] = null;
    renderLogChannels();
    toast('ถอดห้องออกจาก config แล้ว', 'success');
  } catch { toast('❌ เกิดข้อผิดพลาด', 'error'); }
}

// ─── LOAD / SAVE CONFIG ───────────────────────────────────────────
async function loadConfig() {
  try {
    const r = await fetch(`${API_BASE}/api/config?token=${encodeURIComponent(getToken())}`);
    if (!r.ok) throw new Error('unauthorized');
    CFG = await r.json();

    // Populate feature pages
    renderAllPages(CFG);
    renderHomeStatus(CFG);

    // AutoMod
    const am = CFG.automod || {};
    setCheck('am-enabled', am.enabled);
    setCheck('am-links',   am.filter_links);
    setCheck('am-invites', am.filter_invites);
    setCheck('am-caps',    am.filter_caps);
    setVal('am-mute-dur',  am.mute_duration || 5);
    buildPunishWrap('pun-automod', am.punishment || 'timeout');
    savedWords = [...(am.banned_words || [])];
    renderChips();

    // Welcome
    const wlc = CFG.welcome || {};
    setCheck('wlc-en', wlc.enabled);
    setVal('wlc-ch',  wlc.channel_id || '');
    setVal('wlc-msg', wlc.message || '');

    // Whitelist
    const wl = CFG.whitelist || {};
    wlUserIds  = (wl.users||[]).map(String);
    wlRoleIds  = (wl.roles||[]).map(String);
    setVal('wl-bots',  ((CFG.anti_bot_add||{}).bot_whitelist||[]).join('\n'));
    await loadWlRoles();
    renderWlRoleChips();
    renderWlUserChips();

    // Settings
    setVal('bl-role-id', CFG.blacklist_role_id || '');

    // Main log channel
    setVal('main-log-ch', CFG.log_channel_id || '');

    // Log channels
    logChConfig = {...(CFG.log_channels || {})};
    renderLogChannels();
    // Update protection donut chart
    updateCharts(CFG, null);

    // โหลดสถานะ advanced_mode กลับใส่ checkbox
    const advModes = CFG.advanced_mode || {};
    const ADV_KEYS = [
      'anti_ban','anti_kick','anti_ch_create','anti_ch_delete','anti_ch_update',
      'anti_role_create','anti_role_delete','anti_role_update','anti_role_give',
      'anti_webhook_create','anti_webhook_delete','anti_bot_add','anti_guild_update',
      'anti_vanity','anti_prune','anti_integration',
      'anti_join_flood',
      'anti_mass_mentions','anti_text_spam','anti_link_spam','anti_att_spam','anti_emoji_spam',
    ];
    for (const key of ADV_KEYS) {
      const cb = document.getElementById('adv-en-' + key);
      if (cb) cb.checked = !!advModes[key];
    }

    // sync timeout duration กลับใส่ feat cards ทุกตัวที่มี dur field
    // [Audit Session 5] แก้: element ID ต้องตรงกับที่ buildFeatureCard สร้าง (feat-timeout-dur-/feat-timeout-unit-)
    const ALL_FEAT_KEYS = [
      'anti_ban','anti_kick','anti_ch_create','anti_ch_delete','anti_ch_update',
      'anti_role_create','anti_role_delete','anti_role_update','anti_role_give',
      'anti_webhook_create','anti_webhook_delete','anti_bot_add','anti_guild_update',
      'anti_vanity','anti_prune','anti_integration',
      'anti_join_flood',
      'anti_mass_mentions','anti_text_spam','anti_link_spam','anti_att_spam','anti_emoji_spam',
    ];
    for (const key of ALL_FEAT_KEYS) {
      const feat = CFG[key] || {};
      const durEl   = document.getElementById('feat-timeout-dur-' + key);
      const unitEl  = document.getElementById('feat-timeout-unit-' + key);
      const durRow  = document.getElementById('timeout-dur-field-' + key);
      const punish  = feat.punishment || 'ban';
      if (durEl && unitEl) {
        const rawSec = feat.timeout_duration ?? 300;
        if (rawSec % 86400 === 0) { durEl.value = rawSec/86400; unitEl.value = 'd'; }
        else if (rawSec % 3600 === 0) { durEl.value = rawSec/3600; unitEl.value = 'h'; }
        else if (rawSec % 60 === 0)   { durEl.value = rawSec/60;   unitEl.value = 'm'; }
        else { durEl.value = rawSec; unitEl.value = 's'; }
      }
      if (durRow) durRow.style.display = (punish === 'timeout') ? 'block' : 'none';
    }

  } catch(e) {
    if (e.message && e.message.includes('Session')) return;
    toast('โหลด config ไม่ได้: ' + e.message, 'error');
  }
}

async function saveConfig() {
  const payload = {};

  // Collect all standard feature values (toggle + limit + window + punishment)
  const FEAT_KEYS = [
    'anti_ban','anti_kick','anti_ch_create','anti_ch_delete','anti_ch_update',
    'anti_role_create','anti_role_delete','anti_role_update','anti_role_give',
    'anti_webhook_create','anti_webhook_delete','anti_bot_add','anti_guild_update',
    'anti_vanity','anti_prune','anti_integration',
    'anti_join_flood',
    'anti_mass_mentions','anti_text_spam','anti_link_spam','anti_att_spam','anti_emoji_spam',
  ];
  const advModePayload = {};
  for (const key of FEAT_KEYS) {
    const enEl = document.getElementById('feat-en-' + key);
    if (enEl) {
      const val = getFeatVal(key);
      // แยก _adv_mode ออกก่อนส่ง config ปกติ
      const { _adv_mode, ...featVal } = val;
      payload[key] = featVal;
      advModePayload[key] = _adv_mode;
    }
  }
  payload['advanced_mode'] = advModePayload;

  // Anti-Account Age — limit = min days, no window
  const aaEl = document.getElementById('feat-en-anti_account_age');
  if (aaEl) {
    payload['anti_account_age'] = {
      enabled:    aaEl.checked,
      limit:      parseInt(document.getElementById('feat-limit-anti_account_age')?.value) || 7,
      punishment: document.getElementById('punish-anti_account_age')?.dataset.val || 'kick',
    };
  }

  // Anti-No Avatar — toggle + punishment only
  const naEl = document.getElementById('feat-en-anti_no_avatar');
  if (naEl) {
    payload['anti_no_avatar'] = {
      enabled:    naEl.checked,
      punishment: document.getElementById('punish-anti_no_avatar')?.dataset.val || 'kick',
    };
  }

  // Lockdown
  const ldEl = document.getElementById('feat-en-server_lockdown');
  if (ldEl) payload['server_lockdown'] = {enabled: ldEl.checked};

  // Voice abuse
  const vaEn    = document.getElementById('feat-en-voiceabuse');
  const vaLimit = document.getElementById('feat-limit-voiceabuse');
  const vaWin   = document.getElementById('feat-window-voiceabuse');
  const vaMute  = document.getElementById('va-mute-dur');
  const vaPun   = document.getElementById('punish-voiceabuse');
  // [Session 6] แก้: voiceabuse window ต้องผ่าน toSeconds() เหมือน feature อื่น
  const vaWinUnit = document.getElementById('va-window-unit');
  if (vaEn) payload['voiceabuse'] = {
    enabled:       vaEn.checked,
    limit:         parseInt(vaLimit?.value)||5,
    window:        vaWin ? toSeconds(vaWin.value, vaWinUnit?.value||'s') : 10,
    punishment:    vaPun?.dataset.val || 'timeout',
    mute_duration: parseInt(vaMute?.value)||10,
  };

  // AutoMod
  const amPun = document.getElementById('pun-automod');
  payload['automod'] = {
    enabled:        getCheck('am-enabled'),
    filter_links:   getCheck('am-links'),
    filter_invites: getCheck('am-invites'),
    filter_caps:    getCheck('am-caps'),
    punishment:     amPun ? (amPun.dataset.val || 'timeout') : 'timeout',
    mute_duration:  parseInt(getVal('am-mute-dur')) || 5,
    banned_words:   savedWords,
  };

  // Welcome
  payload['welcome'] = {
    enabled:    getCheck('wlc-en'),
    channel_id: getVal('wlc-ch') || null,
    message:    getVal('wlc-msg'),
  };

  // Whitelist
  payload['whitelist'] = {
    users: wlUserIds,
    roles: wlRoleIds,
  };

  // Bot whitelist (inside anti_bot_add — merge ไม่ overwrite)
  if (payload['anti_bot_add']) {
    payload['anti_bot_add'].bot_whitelist = getVal('wl-bots')
      .split('\n').map(s => s.trim()).filter(Boolean);
  } else {
    // anti_bot_add อาจไม่ได้อยู่ใน FEAT_KEYS render แล้ว ต้อง set แยก
    const abEl = document.getElementById('feat-en-anti_bot_add');
    if (abEl) {
      payload['anti_bot_add'] = {
        ...getFeatVal('anti_bot_add'),
        bot_whitelist: getVal('wl-bots').split('\n').map(s=>s.trim()).filter(Boolean),
      };
    }
  }

  // Settings
  payload['blacklist_role_id'] = getVal('bl-role-id') || null;
  payload['log_channel_id']    = getVal('main-log-ch') || null;

  try {
    const r = await fetch(`${API_BASE}/api/config?token=${encodeURIComponent(getToken())}`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify(payload)
    });
    const d = await r.json();
    if (r.status === 401) { handleSessionExpired(); return; }
    if (!r.ok) throw new Error(d.error);
    CFG = {...CFG, ...payload};
    renderHomeStatus(CFG);
    toast('บันทึกเรียบร้อยแล้ว', 'success');
  } catch(e) {
    if (e.message && e.message.includes('Session')) return;
    toast('บันทึกไม่ได้: ' + e.message, 'error');
  }
}

// ─── STATS ────────────────────────────────────────────────────────
async function loadStats() {
  try {
    const r = await fetch(`${API_BASE}/api/stats?token=${encodeURIComponent(getToken())}`);
    if (r.status === 401) { handleSessionExpired(); return; }
    if (!r.ok) return;
    const d = await r.json();
    // Banner
    document.getElementById('ban-name').textContent    = d.guild_name || '-';
    document.getElementById('ban-members').textContent = `${d.member_count} สมาชิก • ${d.online_count} ออนไลน์`;
    const banIcon = document.getElementById('ban-icon');
    if (d.icon_url) banIcon.innerHTML = `<img src="${d.icon_url}" alt="icon"/>`;
    // [Session 5] Server banner image — ใช้ banner_url ก่อน ถ้าไม่มีใช้ splash_url
    const bannerEl  = document.getElementById('server-banner');
    const bannerImg = document.getElementById('banner-img');
    const bannerOvl = document.getElementById('banner-overlay');
    const bannerSrc = d.banner_url || d.splash_url || '';
    if (bannerSrc && bannerImg) {
      bannerImg.src = bannerSrc;
      bannerImg.style.display = 'block';
      if (bannerOvl) bannerOvl.style.display = 'block';
      if (bannerEl)  bannerEl.classList.add('has-banner');
    } else {
      if (bannerImg) bannerImg.style.display = 'none';
      if (bannerOvl) bannerOvl.style.display = 'none';
      if (bannerEl)  bannerEl.classList.remove('has-banner');
    }
    // Sidebar
    document.getElementById('sb-sname').textContent = d.guild_name || '-';
    document.getElementById('sb-sid').textContent   = d.server_id  || '-';
    const sbIw = document.getElementById('sb-icon-wrap');
    if (d.icon_url) sbIw.innerHTML = `<img src="${d.icon_url}" alt="icon"/>`;
    // Stats
    setHtml('st-members',  d.member_count);
    setHtml('st-online',   d.online_count);
    setHtml('st-channels', d.channel_count);
    setHtml('st-roles',    d.role_count);
    document.querySelectorAll('.stat-num.skeleton').forEach(e => e.classList.remove('skeleton'));
    // Lockdown banner
    const ldBanner = document.getElementById('ld-banner');
    if (ldBanner) ldBanner.classList.toggle('hidden', !d.in_lockdown);
    // Raid mode banner
    const raidBanner = document.getElementById('raid-banner');
    if (raidBanner) raidBanner.classList.toggle('hidden', !d.raid_mode);
    // Update server chart
    updateCharts(CFG, d);
  } catch(e) { console.error(e); }  // [Audit Session 5] แก้: log.error ไม่มีใน JS → ใช้ console.error แทน
}

// ─── LOCKDOWN ─────────────────────────────────────────────────────
async function toggleLockdown(enable) {
  try {
    const r = await fetch(`${API_BASE}/api/lockdown?token=${encodeURIComponent(getToken())}`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({enable})
    });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error);
    const ldBanner = document.getElementById('ld-banner');
    if (ldBanner) ldBanner.classList.toggle('hidden', !enable);
    const ldEl = document.getElementById('feat-en-server_lockdown');
    if (ldEl) ldEl.checked = enable;
    toggleFeatCard('server_lockdown', enable);
    toast(enable ? 'Lockdown เปิดแล้ว' : 'Lockdown ปิดแล้ว', enable?'error':'success');
  } catch(e) { toast(e.message, 'error'); }
}

// ─── LOGS ─────────────────────────────────────────────────────────
const LOG_COLORS = {
  ban:'#ff4757', kick:'#ffa502', message_delete:'#d29922',
  channel_delete:'#ff4757', role_delete:'#ff4757',
  member_update:'#3b6ef8', member_ban:'#ff4757', member_kick:'#ffa502',
};

async function loadLogs() {
  const list = document.getElementById('log-list');
  list.innerHTML = '<div style="padding:24px;text-align:center;color:var(--muted);"><div class="loader" style="margin:auto;"></div></div>';
  try {
    const r = await fetch(`${API_BASE}/api/logs?token=${encodeURIComponent(getToken())}`);
    if (!r.ok) throw new Error();
    const logs = await r.json();
    if (!logs.length) { list.innerHTML='<div style="padding:24px;text-align:center;color:var(--muted);">ไม่มีบันทึก</div>'; return; }
    list.innerHTML = logs.map(l => {
      const action = (l.action||'').replace(/_/g,' ');
      const color  = LOG_COLORS[(l.action||'').toLowerCase()] || '#3d5478';
      const dt = l.timestamp ? new Date(l.timestamp).toLocaleString('th-TH',{hour:'2-digit',minute:'2-digit',day:'numeric',month:'short'}) : '';
      return `<div class="log-item">
        <span class="log-badge" style="background:${color}22;color:${color};">${action}</span>
        <div class="log-body">
          <div class="log-action">${escHtml(l.user||'-')}</div>
          <div class="log-meta">เป้าหมาย: ${escHtml(String(l.target||'-'))}${l.reason&&l.reason!=='-'?' • '+escHtml(l.reason):''}</div>
        </div>
        <div class="log-time">${dt}</div>
      </div>`;
    }).join('');
  } catch {
    list.innerHTML='<div style="padding:24px;text-align:center;color:var(--muted);">โหลดบันทึกไม่ได้</div>';
  }
}

// ─── CHIPS (Banned Words) ─────────────────────────────────────────
function renderChips() {
  const wrap = document.getElementById('bw-chips');
  if (!wrap) return;
  wrap.innerHTML = savedWords.map((w,i) =>
    `<div class="chip">${escHtml(w)}<button onclick="removeWord(${i})">×</button></div>`
  ).join('');
}
function removeWord(i) { savedWords.splice(i,1); renderChips(); }
document.addEventListener('keydown', e => {
  const inp = document.getElementById('bw-inp');
  if (e.key === 'Enter' && document.activeElement === inp) {
    const val = inp.value.trim();
    if (val && !savedWords.includes(val)) { savedWords.push(val); renderChips(); }
    inp.value = '';
  }
});

// ─── PAGE NAVIGATION ──────────────────────────────────────────────
const PAGE_TITLES = {
  threat:        ['Threat Dashboard',    'ภาพรวม Real-time ของทุกระบบป้องกัน'],
  timeline:      ['Action Timeline',     'ไทม์ไลน์เหตุการณ์ทั้งหมดที่บอททำ'],
  weeklyreport:  ['Weekly Report',       'สรุปสถิติและการป้องกันรายสัปดาห์'],
  home:          ['หน้าหลัก',           'ภาพรวมของ Server'],
  antinuke:      ['Anti-Nuke',           'ป้องกันการทำลายเซิร์ฟเวอร์'],
  antiraid:      ['Anti-Raid',           'สกัดกั้นการโจมตีและบัญชีอวตาร'],
  lockdown:      ['Server Lockdown',     'ล็อกทุกช่องทางในกรณีฉุกเฉิน'],
  antispam:      ['Anti-Spam',           'รักษาความสงบในช่องแชท'],
  automod:       ['Auto Mod',            'กรองข้อความอัตโนมัติ'],
  voiceabuse:    ['Voice Abuse',         'ป้องกันการใช้ Voice ในทางที่ผิด'],
  welcome:       ['Welcome',             'ข้อความต้อนรับสมาชิกใหม่'],
  whitelist:     ['Whitelist',            'ข้ามการตรวจสอบทั้งหมด'],
  memberprofile: ['โปรไฟล์สมาชิก',       'ดูโปรไฟล์และตั้งค่าการยกเว้นรายบุคคล'],
  suspicious:    ['พฤติกรรมน่าสงสัย',     'แจ้งเตือนพฤติกรรมผิดปกติในเซิร์ฟเวอร์'],
  roleinspector: ['Role Inspector',      'ดูสิทธิ์ห้องของแต่ละยศ'],
  rolemanager:   ['Role Manager',        'ตั้งค่ายศสำหรับ Advanced Lockdown'],
  logchannels:   ['Log Channels',        'ห้อง Log อัตโนมัติ'],
  settings:      ['ตั้งค่าทั่วไป',      'การตั้งค่าหลักของบอท'],
  logs:          ['Audit Log',           'ประวัติการกระทำใน Server'],
  userinstall:   ['User-Install Guard',  'ป้องกัน User-Installed Apps ใน Server'],
};

function goPage(id) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-item,.bnav-item').forEach(n => n.classList.remove('active'));
  const page = document.getElementById('page-' + id);
  if (page) page.classList.add('active');
  const info = PAGE_TITLES[id] || [id,''];
  document.getElementById('page-title').textContent = info[0];
  document.getElementById('page-sub').textContent   = info[1];
  document.querySelectorAll('.nav-item,.bnav-item').forEach(n => {
    if (n.getAttribute('onclick') === `goPage('${id}')`) n.classList.add('active');
  });
  if (window.lucide) lucide.createIcons();
  if (id === 'logs')          loadLogs();
  if (id === 'roleinspector') loadRoleInspector();
  if (id === 'suspicious')    loadSuspiciousAlerts();
  if (id === 'memberprofile') mpRenderRecent();
  if (id === 'rolemanager')   rmLoad();
  if (id === 'userinstall')   uiLoad();
  if (id === 'threat')        loadThreatDashboard();
  if (id === 'timeline')      loadTimeline();
  if (id === 'weeklyreport')  loadWeeklyReport();
}

// ─── INIT BL (call !initbl equivalent via bot) ────────────────────
// Since !initbl is a Discord command, we guide the user
function sendInitBl() {
  toast('พิมพ์ !initbl ใน Discord แล้วบอทจะสร้างยศ Blacklist ให้อัตโนมัติ', 'success', 5000);
}

// ─── AUTH ─────────────────────────────────────────────────────────
async function doLogin() {
  const t = document.getElementById('token-inp').value.trim();
  if (!t) return;
  try {
    const r = await fetch(`${API_BASE}/api/verify?token=${encodeURIComponent(t)}`);
    const d = await r.json();
    if (!d.valid) { document.getElementById('login-err').classList.add('show'); return; }
    setToken(t);
    showApp();
  } catch { document.getElementById('login-err').classList.add('show'); }
}

function showApp() {
  document.getElementById('login-view').classList.add('hidden');
  document.getElementById('app-view').classList.add('active');
  if (window.lucide) lucide.createIcons();
  setTimeout(initCharts, 100);
  loadConfig();
  loadStats();
  setTimeout(validateChannels, 2000);  // ตรวจห้องที่ถูกลบหลังโหลดเสร็จ
  setInterval(loadStats, 30000);
  setInterval(validateChannels, 300000); // ตรวจซ้ำทุก 5 นาที
}

function doLogout() {
  sessionStorage.removeItem('sb_token');
  location.reload();
}

document.getElementById('token-inp').addEventListener('keydown', e => {
  if (e.key === 'Enter') doLogin();
});

// ─── UTILS ────────────────────────────────────────────────────────
function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function setCheck(id, v) { const el = document.getElementById(id); if (el) el.checked = !!v; }
function getCheck(id) { const el = document.getElementById(id); return el ? el.checked : false; }
function setVal(id, v) { const el = document.getElementById(id); if (el) el.value = v ?? ''; }
function getVal(id) { const el = document.getElementById(id); return el ? el.value : ''; }
function setHtml(id, v) { const el = document.getElementById(id); if (el) el.textContent = v; }

function toast(msg, type='success', dur=3500) {
  const wrap = document.getElementById('toast-wrap');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = msg;
  wrap.appendChild(el);
  setTimeout(() => { el.classList.add('fade-out'); setTimeout(()=>el.remove(), 300); }, dur);
}

// ─── WHITELIST ROLE + MEMBER ──────────────────────────────────────
let wlSearchTimer = null;

async function loadWlRoles() {
  try {
    const r = await fetch(`${API_BASE}/api/roles?token=${encodeURIComponent(getToken())}`);
    if (!r.ok) return;
    wlRoleData = await r.json();
    const sel = document.getElementById('wl-role-select');
    if (!sel) return;
    sel.innerHTML = '<option value="">— เลือกยศ —</option>' +
      wlRoleData.map(ro =>
        `<option value="${ro.id}">${escHtml(ro.name)}</option>`
      ).join('');
  } catch(e) { console.error('loadWlRoles', e); }
}

function renderWlRoleChips() {
  const wrap = document.getElementById('wl-role-chips');
  if (!wrap) return;
  wrap.innerHTML = wlRoleIds.map(id => {
    const ro = wlRoleData.find(r => r.id === id);
    const name = ro ? ro.name : id;
    return `<div class="chip"><svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:3px;"><path d="M12 2H2v10l9.29 9.29c.94.94 2.48.94 3.42 0l6.58-6.58c.94-.94.94-2.48 0-3.42L12 2Z"/><path d="M7 7h.01"/></svg> ${escHtml(name)}<button onclick="wlRemoveRole('${id}')">×</button></div>`;
  }).join('');
  if (window.lucide) lucide.createIcons();
}

function renderWlUserChips() {
  const wrap = document.getElementById('wl-user-chips');
  if (!wrap) return;
  wrap.innerHTML = wlUserIds.map(id => {
    const u = wlUserData[id];
    const name = u ? (u.display_name || u.name) : id;
    return `<div class="chip"><svg xmlns="http://www.w3.org/2000/svg" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:3px;"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg> ${escHtml(name)}<button onclick="wlRemoveUser('${id}')">×</button></div>`;
  }).join('');
  if (window.lucide) lucide.createIcons();
}

function wlAddRole() {
  const sel = document.getElementById('wl-role-select');
  if (!sel || !sel.value) return;
  if (!wlRoleIds.includes(sel.value)) {
    wlRoleIds.push(sel.value);
    renderWlRoleChips();
  }
  sel.value = '';
}

function wlRemoveRole(id) {
  wlRoleIds = wlRoleIds.filter(r => r !== id);
  renderWlRoleChips();
}

function wlRemoveUser(id) {
  wlUserIds = wlUserIds.filter(u => u !== id);
  renderWlUserChips();
}

function wlSearchMembers(q) {
  clearTimeout(wlSearchTimer);
  const dd = document.getElementById('wl-member-dropdown');
  if (!q.trim()) { dd.style.display = 'none'; return; }
  wlSearchTimer = setTimeout(async () => {
    try {
      const r = await fetch(`${API_BASE}/api/members?token=${encodeURIComponent(getToken())}&q=${encodeURIComponent(q)}`);
      if (!r.ok) return;
      const members = await r.json();
      if (!members.length) {
        dd.style.display = 'none'; return;
      }
      dd.innerHTML = members.map(m => {
        const mJson = escHtml(JSON.stringify({id:m.id, name:m.name, display_name:m.display_name, global_name:m.global_name, avatar:m.avatar}));
        return `
        <div onclick="wlSelectMember('${m.id}', JSON.parse(decodeURIComponent('${encodeURIComponent(JSON.stringify({id:m.id,name:m.name,display_name:m.display_name,global_name:m.global_name,avatar:m.avatar}))}'.replace(/\\+/g,' '))))"
             style="display:flex;align-items:center;gap:10px;padding:9px 13px;cursor:pointer;
                    border-bottom:1px solid var(--border);transition:background .12s;"
             onmouseover="this.style.background='var(--surface3)'"
             onmouseout="this.style.background=''">
          <img src="${escHtml(m.avatar)}" alt="" style="width:30px;height:30px;border-radius:50%;flex-shrink:0;"/>
          <div>
            <div style="font-size:13px;font-weight:600;color:var(--text);">${escHtml(m.display_name)}</div>
            <div style="font-size:11px;color:var(--muted);">${escHtml(m.name)} • ${m.id}</div>
          </div>
        </div>`;
      }).join('');
      dd.style.display = 'block';
    } catch(e) { console.error('wlSearch', e); }
  }, 250);
}

function wlSelectMember(id, memberData) {
  // ถ้ามี memberData ส่งมาแล้ว ใช้เลย (จาก dropdown ที่ render ไว้)
  if (memberData) {
    wlUserData[id] = memberData;
    if (!wlUserIds.includes(id)) {
      wlUserIds.push(id);
      renderWlUserChips();
    }
  } else {
    // fallback: ดึงจาก API
    fetch(`${API_BASE}/api/member-detail?token=${encodeURIComponent(getToken())}&member_id=${id}`)
      .then(r => r.json()).then(m => {
        if (m && m.id) wlUserData[id] = m;
        if (!wlUserIds.includes(id)) {
          wlUserIds.push(id);
          renderWlUserChips();
        }
      }).catch(() => {
        // เพิ่ม ID ไว้ก่อนแม้โหลดชื่อไม่ได้
        if (!wlUserIds.includes(id)) {
          wlUserIds.push(id);
          renderWlUserChips();
        }
      });
  }
  document.getElementById('wl-member-search').value = '';
  document.getElementById('wl-member-dropdown').style.display = 'none';
}

// Close member dropdown when clicking outside
document.addEventListener('click', e => {
  const dd = document.getElementById('wl-member-dropdown');
  const inp = document.getElementById('wl-member-search');
  if (dd && inp && !dd.contains(e.target) && e.target !== inp) {
    dd.style.display = 'none';
  }
});

// ─── MEMBER PROFILE ───────────────────────────────────────────────
let mpSearchTimer = null;
let mpCurrentMemberId = null;
let mpRecentMembers = JSON.parse(localStorage.getItem('mpRecent') || '[]');

function mpSaveRecent(m) {
  mpRecentMembers = mpRecentMembers.filter(r => r.id !== m.id);
  mpRecentMembers.unshift(m);
  if (mpRecentMembers.length > 20) mpRecentMembers = mpRecentMembers.slice(0, 20);
  try { localStorage.setItem('mpRecent', JSON.stringify(mpRecentMembers)); } catch(e) {}
}

function mpRenderRecent() {
  const list = document.getElementById('mp-recent-list');
  if (!list) return;
  if (!mpRecentMembers.length) {
    list.innerHTML = '<div style="color:var(--muted);font-size:13px;text-align:center;padding:18px 0;">ยังไม่มีประวัติการดู — ค้นหาและเลือกสมาชิกด้านบน</div>';
    return;
  }
  list.innerHTML = mpRecentMembers.map(m => `
    <div style="display:flex;align-items:center;gap:12px;padding:10px 12px;
                background:var(--surface2);border-radius:10px;margin-bottom:6px;
                cursor:pointer;border:1px solid var(--border);transition:all .15s;"
         onclick="mpSelectMember('${m.id}')"
         onmouseover="this.style.borderColor='var(--border2)'"
         onmouseout="this.style.borderColor='var(--border)'">
      <img src="${escHtml(m.avatar||'')}" alt="" onerror="this.style.display='none'"
           style="width:38px;height:38px;border-radius:50%;border:1.5px solid var(--border2);flex-shrink:0;"/>
      <div style="flex:1;min-width:0;">
        <div style="font-size:13px;font-weight:700;color:var(--text);">${escHtml(m.display_name||m.name)}</div>
        <div style="font-size:11px;color:var(--muted);">${escHtml(m.name)} • ${m.id}</div>
      </div>
      <button onclick="event.stopPropagation();mpShowSettingsFor('${m.id}')"
              title="ดูการตั้งค่าการยกเว้น"
              style="background:var(--surface3);border:1px solid var(--border);border-radius:7px;
                     padding:6px 9px;font-size:15px;cursor:pointer;color:var(--muted);
                     transition:all .15s;flex-shrink:0;"
              onmouseover="this.style.color='var(--text)'"
              onmouseout="this.style.color='var(--muted)'"><svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z"/><circle cx="12" cy="12" r="3"/></svg></button>
    </div>`).join('');
  if (window.lucide) lucide.createIcons();
}

async function mpShowSettingsFor(id) {
  await mpSelectMember(id);
  document.getElementById('mp-settings-panel').style.display = 'block';
}

function mpToggleSettings() {
  const p = document.getElementById('mp-settings-panel');
  p.style.display = p.style.display === 'none' ? 'block' : 'none';
}

function mpSearch(q) {
  clearTimeout(mpSearchTimer);
  const dd = document.getElementById('mp-dropdown');
  if (!q.trim()) { dd.style.display = 'none'; return; }
  mpSearchTimer = setTimeout(async () => {
    try {
      const r = await fetch(`${API_BASE}/api/members?token=${encodeURIComponent(getToken())}&q=${encodeURIComponent(q)}`);
      if (!r.ok) return;
      const members = await r.json();
      if (!members.length) { dd.style.display = 'none'; return; }
      dd.innerHTML = members.map(m => `
        <div onclick="mpSelectMember('${m.id}')"
             style="display:flex;align-items:center;gap:10px;padding:9px 13px;cursor:pointer;
                    border-bottom:1px solid var(--border);transition:background .12s;"
             onmouseover="this.style.background='var(--surface3)'"
             onmouseout="this.style.background=''">
          <img src="${escHtml(m.avatar)}" alt="" style="width:30px;height:30px;border-radius:50%;flex-shrink:0;"/>
          <div>
            <div style="font-size:13px;font-weight:600;color:var(--text);">${escHtml(m.display_name)}</div>
            <div style="font-size:11px;color:var(--muted);">${escHtml(m.name)} • ${m.id}</div>
          </div>
        </div>`).join('');
      dd.style.display = 'block';
    } catch(e) { console.error('mpSearch', e); }
  }, 250);
}

async function mpSelectMember(id) {
  document.getElementById('mp-dropdown').style.display = 'none';
  document.getElementById('mp-search').value = '';
  mpCurrentMemberId = id;
  document.getElementById('mp-settings-panel').style.display = 'none';
  try {
    const r = await fetch(`${API_BASE}/api/member-detail?token=${encodeURIComponent(getToken())}&member_id=${id}`);
    if (!r.ok) { toast('ไม่พบสมาชิก','error'); return; }
    const m = await r.json();

    // Save to recent
    mpSaveRecent({ id: m.id, name: m.name, display_name: m.display_name, avatar: m.avatar });
    mpRenderRecent();

    document.getElementById('mp-avatar').src = m.avatar;
    document.getElementById('mp-name').textContent = m.display_name + (m.is_owner ? ' ★' : '');
    document.getElementById('mp-username').textContent = m.name;
    document.getElementById('mp-id').textContent = 'ID: ' + m.id;
    document.getElementById('mp-joined').textContent = m.joined_at ? new Date(m.joined_at).toLocaleDateString('th-TH') : '—';
    document.getElementById('mp-created').textContent = new Date(m.created_at).toLocaleDateString('th-TH');

    const rolesEl = document.getElementById('mp-roles');
    rolesEl.innerHTML = m.roles.length
      ? m.roles.map(ro => {
          const c = ro.color !== '#000000' ? ro.color : 'var(--border2)';
          return `<div class="chip" style="border-color:${c};"><svg xmlns="http://www.w3.org/2000/svg" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" style="margin-right:3px;"><path d="M12 2H2v10l9.29 9.29c.94.94 2.48.94 3.42 0l6.58-6.58c.94-.94.94-2.48 0-3.42L12 2Z"/><path d="M7 7h.01"/></svg>${escHtml(ro.name)}</div>`;
        }).join('')
      : '<span style="color:var(--muted);font-size:12px;">ไม่มียศพิเศษ</span>';
    if (window.lucide) lucide.createIcons();

    // Load exemptions
    const ex = m.exemptions || {};
    setCheck('ex-all',     ex.all     || false);
    setCheck('ex-spam',    ex.spam    || false);
    setCheck('ex-links',   ex.links   || false);
    setCheck('ex-mentions',ex.mentions|| false);
    setCheck('ex-raid',    ex.raid    || false);
    setCheck('ex-nuke',    ex.nuke    || false);
    setCheck('ex-automod', ex.automod || false);
    setCheck('ex-voice',   ex.voice   || false);

    document.getElementById('mp-panel').style.display = 'block';
    document.getElementById('mp-panel').scrollIntoView({behavior:'smooth', block:'start'});

    // Load suspicious actions for this member
    loadMemberSuspicious(id);
  } catch(e) { toast('เกิดข้อผิดพลาด','error'); }
}

async function loadMemberSuspicious(memberId) {
  const panel = document.getElementById('mp-suspicious-list');
  if (!panel) return;
  try {
    const r = await fetch(`${API_BASE}/api/member-actions?token=${encodeURIComponent(getToken())}&member_id=${memberId}`);
    if (!r.ok) { panel.innerHTML = '<div style="color:var(--muted);font-size:13px;text-align:center;padding:12px;">ไม่มีข้อมูล</div>'; return; }
    const actions = await r.json();
    if (!actions.length) {
      panel.innerHTML = '<div style="color:var(--success);font-size:13px;text-align:center;padding:12px;">ไม่พบการกระทำน่าสงสัย</div>';
      return;
    }
    // Group by key
    const grouped = {};
    actions.forEach(a => { if (!grouped[a.key]) grouped[a.key] = 0; grouped[a.key]++; });
    panel.innerHTML = Object.entries(grouped).map(([k,cnt]) => `
      <div style="display:flex;justify-content:space-between;align-items:center;
                  padding:8px 12px;background:var(--surface2);border-radius:8px;margin-bottom:6px;">
        <span style="font-size:13px;color:var(--text);">${k}</span>
        <span style="font-size:12px;font-weight:700;color:var(--accent);">${cnt} ครั้ง</span>
      </div>`).join('') +
      `<div style="font-size:11px;color:var(--muted);text-align:right;margin-top:4px;">(${actions.length} รายการล่าสุด)</div>`;
  } catch(e) {
    panel.innerHTML = '<div style="color:var(--muted);font-size:13px;text-align:center;padding:12px;">โหลดไม่ได้</div>';
  }
}

function exToggleAll(cb) {
  ['ex-spam','ex-links','ex-mentions','ex-raid','ex-nuke','ex-automod','ex-voice']
    .forEach(id => setCheck(id, cb.checked));
}

async function mpSaveExemptions() {
  if (!mpCurrentMemberId) return;
  const exemptions = {
    all:      getCheck('ex-all'),
    spam:     getCheck('ex-spam'),
    links:    getCheck('ex-links'),
    mentions: getCheck('ex-mentions'),
    raid:     getCheck('ex-raid'),
    nuke:     getCheck('ex-nuke'),
    automod:  getCheck('ex-automod'),
    voice:    getCheck('ex-voice'),
  };
  try {
    const r = await fetch(`${API_BASE}/api/member-exemptions?token=${encodeURIComponent(getToken())}`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({member_id: mpCurrentMemberId, exemptions})
    });
    if (!r.ok) throw new Error();
    toast('บันทึกการตั้งค่าแล้ว');
  } catch(e) { toast('เกิดข้อผิดพลาด','error'); }
}

function mpClearExemptions() {
  ['ex-all','ex-spam','ex-links','ex-mentions','ex-raid','ex-nuke','ex-automod','ex-voice']
    .forEach(id => setCheck(id, false));
}

document.addEventListener('click', e => {
  const dd = document.getElementById('mp-dropdown');
  const inp = document.getElementById('mp-search');
  if (dd && inp && !dd.contains(e.target) && e.target !== inp) dd.style.display = 'none';
});

// ─── SUSPICIOUS ALERTS ────────────────────────────────────────────
let susAllAlerts = [];
let susCurrentFilter = 'all';

async function loadSuspiciousAlerts() {
  const list = document.getElementById('sus-alert-list');
  if (!list) return;
  list.innerHTML = '<div style="color:var(--muted);font-size:13px;text-align:center;padding:30px 0;">⏳ กำลังโหลด...</div>';
  try {
    const r = await fetch(`${API_BASE}/api/suspicious-alerts?token=${encodeURIComponent(getToken())}`);
    if (!r.ok) return;
    susAllAlerts = await r.json();
    susCurrentFilter = 'all';
    susRenderAlerts();
  } catch(e) {
    list.innerHTML = '<div style="color:var(--danger);text-align:center;padding:20px;">โหลดไม่ได้</div>';
  }
}

function susRenderAlerts() {
  const list = document.getElementById('sus-alert-list');
  const SEV_COLOR = { high: '#ff4757', medium: '#ffa502', low: '#2ed573' };
  const SEV_LABEL = { high: 'สูง', medium: 'กลาง', low: 'ต่ำ' };
  const filtered = susAllAlerts.filter(a => {
    if (susCurrentFilter === 'high')   return a.severity === 'high';
    if (susCurrentFilter === 'med')    return a.severity === 'medium';
    if (susCurrentFilter === 'low')    return a.severity === 'low';
    return true;
  });
  if (!filtered.length) {
    list.innerHTML = '<div style="color:var(--success);font-size:14px;text-align:center;padding:40px 0;">ไม่พบพฤติกรรมน่าสงสัย</div>';
    susUpdateFilterBtns();
    return;
  }
  list.innerHTML = filtered.map(a => {
    const color = SEV_COLOR[a.severity] || '#ccc';
    const label = SEV_LABEL[a.severity] || a.severity;
    const timeStr = new Date(a.ts * 1000).toLocaleString('th-TH');
    return `<div style="background:var(--surface);border:1.5px solid ${color}30;border-left:4px solid ${color};
                        border-radius:10px;padding:14px;${a.read ? 'opacity:.65;' : ''}">
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:8px;">
        ${a.member_avatar ? `<img src="${escHtml(a.member_avatar)}" alt=""
             style="width:36px;height:36px;border-radius:50%;border:1.5px solid ${color};flex-shrink:0;"/>` : ''}
        <div style="flex:1;min-width:0;">
          <div style="font-size:14px;font-weight:700;color:#fff;">${escHtml(a.member_name)}</div>
          <div style="font-size:11px;color:var(--muted);">${timeStr}</div>
        </div>
        <span style="background:${color}22;color:${color};border:1px solid ${color}44;
                     border-radius:6px;padding:3px 10px;font-size:11px;font-weight:700;">${label}</span>
      </div>
      <div style="font-size:13px;color:var(--text);margin-bottom:6px;">${escHtml(a.desc)}</div>
      <div style="font-size:12px;color:var(--muted);">
        เกิดขึ้น <strong style="color:${color};">${a.count} ครั้ง</strong> ในช่วง ${a.window} วินาที
        ${a.detail ? `— ${escHtml(a.detail)}` : ''}
      </div>
      <div style="margin-top:10px;display:flex;gap:8px;">
        <button class="btn btn-sm" onclick="mpSelectMember('${a.user_id}');goPage('memberprofile')"
                style="flex:1;">ดูโปรไฟล์</button>
        ${!a.read ? `<button class="btn btn-sm" onclick="susMarkRead('${a.id}',this)"
                style="color:var(--muted);">รับทราบ</button>` : ''}
      </div>
    </div>`;
  }).join('');
  susUpdateFilterBtns();
}

function susUpdateFilterBtns() {
  ['all','high','med','low'].forEach(f => {
    const btn = document.getElementById(`sus-filter-${f}`);
    if (btn) btn.style.background = f === susCurrentFilter ? 'var(--primary-glow)' : '';
  });
}

function susFilter(f) { susCurrentFilter = f; susRenderAlerts(); }

async function susMarkRead(alertId, btn) {
  try {
    await fetch(`${API_BASE}/api/suspicious-alerts/read?token=${encodeURIComponent(getToken())}`, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({id: alertId})
    });
    const a = susAllAlerts.find(x => x.id === alertId);
    if (a) a.read = true;
    susRenderAlerts();
  } catch(e) { toast('เกิดข้อผิดพลาด','error'); }
}

// ─── ROLE INSPECTOR ───────────────────────────────────────────────
let riAllChannels = [];
let riCurrentFilter = 'all';
let riRoleMap = {};  // id -> {name, color}

async function loadRoleInspector() {
  const list = document.getElementById('ri-role-list');
  if (!list) return;
  list.innerHTML = '<div style="color:var(--muted);font-size:13px;">⏳ กำลังโหลดยศ...</div>';
  try {
    const r = await fetch(`${API_BASE}/api/roles?token=${encodeURIComponent(getToken())}`);
    if (!r.ok) return;
    const roles = await r.json();
    riRoleMap = {};
    list.innerHTML = roles.map(ro => {
      const colorHex = (ro.color && ro.color !== '#000000' && ro.color !== '0x000000')
        ? (ro.color.startsWith('#') ? ro.color : '#' + parseInt(ro.color).toString(16).padStart(6,'0'))
        : '#5a7ba0';
      riRoleMap[ro.id] = { name: ro.name, color: colorHex };
      return `<div class="ri-role-item" onclick="riSelectRole('${ro.id}')">
        <div class="ri-role-dot" style="background:${colorHex};box-shadow:0 0 6px ${colorHex}55;"></div>
        <div class="ri-role-name">${escHtml(ro.name)}</div>
        <div class="ri-role-arrow">→</div>
      </div>`;
    }).join('');
  } catch(e) { list.innerHTML = '<div style="color:var(--danger);">โหลดไม่ได้</div>'; }
}

async function riSelectRole(roleId) {
  const meta = riRoleMap[roleId] || { name: roleId, color: '#5a7ba0' };
  document.getElementById('ri-role-name').textContent = meta.name;
  document.getElementById('ri-role-name').style.color = meta.color;
  document.getElementById('ri-panel').style.display = 'block';
  document.getElementById('ri-channel-list').innerHTML = '<div style="color:var(--muted);padding:12px;font-size:13px;">⏳ กำลังโหลดข้อมูลห้อง...</div>';
  document.getElementById('ri-panel').scrollIntoView({behavior:'smooth', block:'start'});

  try {
    const r = await fetch(`${API_BASE}/api/role-channels?token=${encodeURIComponent(getToken())}&role_id=${roleId}`);
    if (!r.ok) throw new Error();
    riAllChannels = await r.json();
    riCurrentFilter = 'all';
    riRenderChannels();

    const canSee  = riAllChannels.filter(c => c.can_view).length;
    const cantSee = riAllChannels.filter(c => !c.can_view).length;
    document.getElementById('ri-can-count').textContent  = `เห็น ${canSee} ห้อง`;
    document.getElementById('ri-cant-count').textContent = `ไม่เห็น ${cantSee} ห้อง`;
  } catch(e) {
    document.getElementById('ri-channel-list').innerHTML = '<div style="color:var(--danger);padding:12px;">โหลดไม่ได้ ลองใหม่</div>';
  }
}

function riRenderChannels() {
  const list = document.getElementById('ri-channel-list');
  const typeIcon = t => t === 'TextChannel' ? '#' : t === 'VoiceChannel' ? '♪' : '■';
  const filtered = riAllChannels.filter(ch => {
    if (riCurrentFilter === 'can')  return ch.can_view;
    if (riCurrentFilter === 'cant') return !ch.can_view;
    return true;
  });

  // Group by category
  const groups = {};
  filtered.forEach(ch => {
    const cat = ch.category || '—';
    if (!groups[cat]) groups[cat] = [];
    groups[cat].push(ch);
  });

  list.innerHTML = Object.entries(groups).map(([cat, chs]) => `
    <div style="margin-top:8px;">
      <div style="font-size:10px;font-weight:700;color:var(--muted2);text-transform:uppercase;
                  letter-spacing:.6px;padding:4px 10px;margin-bottom:2px;">${escHtml(cat)}</div>
      ${chs.map(ch => `
        <div class="ri-ch-row">
          <div class="ri-ch-icon">${typeIcon(ch.type)}</div>
          <div style="flex:1;min-width:0;">
            <div class="ri-ch-name">${escHtml(ch.name)}</div>
          </div>
          <div class="ri-ch-badges">
            ${ch.can_view
              ? `<span class="ri-badge-ok">เห็น</span>`
              : `<span class="ri-badge-no"><svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg> ไม่เห็น</span>`}
            ${ch.can_view
              ? (ch.can_send
                  ? `<span class="ri-badge-ok">พิมพ์ได้</span>`
                  : `<span class="ri-badge-no">พิมพ์ไม่ได้</span>`)
              : ''}
          </div>
        </div>`).join('')}
    </div>`).join('') || '<div style="color:var(--muted);padding:14px;font-size:13px;text-align:center;">ไม่มีห้องที่ตรงตามเงื่อนไข</div>';

  // Highlight active filter btn
  ['all','can','cant'].forEach(f => {
    const btn = document.getElementById(`ri-filter-${f}`);
    if (btn) btn.style.background = f === riCurrentFilter ? 'var(--primary-glow)' : '';
  });
}

function riFilter(f) { riCurrentFilter = f; riRenderChannels(); }
function riClose()   { document.getElementById('ri-panel').style.display = 'none'; }

// ─── ROLE MANAGER ─────────────────────────────────────────────────
let rmData = { member_roles: [], dangerous_roles: [], exempt_roles: [] };
let rmAllRoles = [];

async function rmLoad() {
  try {
    const [rmRes, rolesRes] = await Promise.all([
      apiFetch('/api/role-manager'),
      apiFetch('/api/roles'),
    ]);
    if (rmRes && !rmRes.error) {
      rmData = {
        member_roles:    (rmRes.member_roles    || []).map(String),
        dangerous_roles: (rmRes.dangerous_roles || []).map(String),
        exempt_roles:    (rmRes.exempt_roles    || []).map(String),
      };
    }
    if (rolesRes && Array.isArray(rolesRes)) {
      rmAllRoles = rolesRes;
      rmPopulateSelects();
    }
    rmRender();
  } catch(e) { console.error('rmLoad', e); }
}

function rmPopulateSelects() {
  ['dangerous','member','exempt'].forEach(type => {
    const sel = document.getElementById(`rm-${type}-select`);
    if (!sel) return;
    sel.innerHTML = '<option value="">— เลือกยศที่จะเพิ่ม —</option>';
    rmAllRoles.forEach(r => {
      const opt = document.createElement('option');
      opt.value = r.id;
      opt.textContent = r.name;
      sel.appendChild(opt);
    });
  });
}

function rmRender() {
  const typeMap = {
    dangerous: { key: 'dangerous_roles', color: '#f85149' },
    member:    { key: 'member_roles',    color: 'var(--primary-light)' },
    exempt:    { key: 'exempt_roles',    color: 'var(--success)' },
  };
  Object.entries(typeMap).forEach(([type, { key, color }]) => {
    const container = document.getElementById(`rm-${type}-list`);
    if (!container) return;
    container.innerHTML = '';
    const ids = rmData[key] || [];
    if (ids.length === 0) {
      container.innerHTML = `<span style="font-size:11px;color:var(--muted);padding:4px 0;">— ยังไม่มียศ —</span>`;
      return;
    }
    ids.forEach(id => {
      const role = rmAllRoles.find(r => r.id === id);
      const name = role ? role.name : `ID: ${id}`;
      const tag = document.createElement('div');
      tag.style.cssText = `display:inline-flex;align-items:center;gap:5px;background:rgba(255,255,255,.06);border:1px solid ${color}44;border-radius:6px;padding:3px 8px;font-size:11px;color:${color};`;
      tag.innerHTML = `<span>${escHtml(name)}</span><span onclick="rmRemoveRole('${type}','${id}')" style="cursor:pointer;opacity:.7;line-height:1;">✕</span>`;
      container.appendChild(tag);
    });
  });
}

function rmAddRole(type) {
  const keyMap = { dangerous: 'dangerous_roles', member: 'member_roles', exempt: 'exempt_roles' };
  const sel = document.getElementById(`rm-${type}-select`);
  const id  = sel ? sel.value : '';
  if (!id) return;
  const key = keyMap[type];
  if (!rmData[key].includes(id)) {
    rmData[key].push(id);
    rmRender();
  }
  sel.value = '';
}

function rmRemoveRole(type, id) {
  const keyMap = { dangerous: 'dangerous_roles', member: 'member_roles', exempt: 'exempt_roles' };
  const key = keyMap[type];
  rmData[key] = rmData[key].filter(x => x !== id);
  rmRender();
}

async function rmSave() {
  const btn = document.getElementById('rm-save-btn');
  const status = document.getElementById('rm-status');
  btn.disabled = true;
  btn.textContent = 'กำลังบันทึก...';
  try {
    const res = await apiFetch('/api/role-manager', 'POST', rmData);
    if (res && res.success) {
      status.style.color = 'var(--success)';
      status.textContent = '✅ บันทึกสำเร็จ — Advanced Lockdown จะใช้ Role Manager แล้ว';
    } else {
      status.style.color = 'var(--danger)';
      status.textContent = '❌ บันทึกไม่สำเร็จ: ' + (res?.error || 'unknown');
    }
  } catch(e) {
    status.style.color = 'var(--danger)';
    status.textContent = '❌ Error: ' + e.message;
  }
  btn.disabled = false;
  btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right:6px;"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>บันทึก Role Manager';
  setTimeout(() => { status.textContent = ''; }, 4000);
}

async function rmAutoClassify() {
  const btn = document.getElementById('rm-auto-btn');
  if (!btn) return;
  btn.disabled = true;
  btn.textContent = '⏳ กำลังวิเคราะห์...';
  try {
    const res = await apiFetch('/api/role-manager/auto-classify', 'POST', {});
    if (res && res.success) {
      rmData = {
        dangerous_roles: (res.dangerous_roles || []).map(String),
        member_roles:    (res.member_roles    || []).map(String),
        exempt_roles:    (res.exempt_roles    || []).map(String),
      };
      rmRender();
      toast(`✅ แยกยศอัตโนมัติแล้ว — อันตราย: ${res.dangerous_roles.length} | สมาชิก: ${res.member_roles.length}`, 'success', 5000);
    } else {
      toast('❌ Auto-classify ไม่สำเร็จ', 'error');
    }
  } catch(e) {
    toast('❌ Error: ' + e.message, 'error');
  }
  btn.disabled = false;
  btn.innerHTML = '⚡ Auto-classify ยศอัตโนมัติ';
}

// ─── CHARTS ───────────────────────────────────────────────────────
let chartProtection = null;
let chartServer = null;

function initCharts() {
  const chartDefaults = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false }, tooltip: { enabled: true } },
  };

  // Protection donut chart
  const ctxP = document.getElementById('chart-protection');
  if (ctxP && !chartProtection) {
    chartProtection = new Chart(ctxP, {
      type: 'doughnut',
      data: {
        labels: ['Anti-Nuke','Anti-Raid','Anti-Spam','ทั่วไป'],
        datasets: [{
          data: [0, 0, 0, 0],
          backgroundColor: ['rgba(255,71,87,.8)','rgba(255,165,2,.8)','rgba(59,110,248,.8)','rgba(0,200,150,.8)'],
          borderColor: 'transparent',
          borderWidth: 0,
          hoverOffset: 4,
        }]
      },
      options: {
        ...chartDefaults,
        cutout: '72%',
        plugins: {
          legend: {
            display: true,
            position: 'right',
            labels: { color: '#5a7ba0', font: { size: 10, family: 'Kanit' }, boxWidth: 10, padding: 8 }
          },
          tooltip: {
            callbacks: {
              label: (ctx) => ` ${ctx.label}: ${ctx.raw} ระบบ`
            }
          }
        }
      }
    });
  }

  // Server bar chart
  const ctxS = document.getElementById('chart-server');
  if (ctxS && !chartServer) {
    chartServer = new Chart(ctxS, {
      type: 'bar',
      data: {
        labels: ['สมาชิก','ออนไลน์','ช่อง','ยศ'],
        datasets: [{
          data: [0, 0, 0, 0],
          backgroundColor: [
            'rgba(59,110,248,.7)',
            'rgba(0,200,150,.7)',
            'rgba(0,212,255,.7)',
            'rgba(168,85,247,.7)',
          ],
          borderRadius: 6,
          borderSkipped: false,
        }]
      },
      options: {
        ...chartDefaults,
        scales: {
          x: { ticks: { color: '#5a7ba0', font: { size: 10, family: 'Kanit' } }, grid: { display: false }, border: { display: false } },
          y: { ticks: { color: '#3d5478', font: { size: 10, family: 'Kanit' }, maxTicksLimit: 4 }, grid: { color: 'rgba(30,45,69,.6)' }, border: { display: false } }
        }
      }
    });
  }
}

function updateCharts(cfg, stats) {
  if (!chartProtection || !chartServer) return;

  // Count enabled per category
  const NUKE_KEYS  = ['anti_ban','anti_kick','anti_ch_create','anti_ch_delete','anti_ch_update','anti_role_create','anti_role_delete','anti_role_update','anti_role_give','anti_webhook_create','anti_webhook_delete','anti_bot_add','anti_guild_update','anti_vanity','anti_prune','anti_integration'];
  const RAID_KEYS  = ['anti_join_flood','anti_account_age','anti_no_avatar','server_lockdown'];
  const SPAM_KEYS  = ['anti_mass_mentions','anti_text_spam','anti_link_spam','anti_att_spam','anti_emoji_spam'];
  const EXTRA_KEYS = ['automod','voiceabuse'];
  const countOn = keys => keys.filter(k => (cfg[k]||{}).enabled).length;

  chartProtection.data.datasets[0].data = [countOn(NUKE_KEYS), countOn(RAID_KEYS), countOn(SPAM_KEYS), countOn(EXTRA_KEYS)];
  chartProtection.update('none');

  if (stats) {
    chartServer.data.datasets[0].data = [stats.member_count||0, stats.online_count||0, stats.channel_count||0, stats.role_count||0];
    chartServer.update('none');
  }
}

// ══════════════════════════════════════════════════════════════════
//  USER-INSTALL GUARD — JS
// ══════════════════════════════════════════════════════════════════
let _uiData = { enabled: false, action: 'delete', timeout_seconds: 300,
                log_to_channel: true, whitelist_users: [], whitelist_apps: [] };

async function uiLoad() {
  try {
    const r = await fetch(`${API_BASE}/api/user-install?token=${getToken()}`);
    if (!r.ok) { toast('โหลด User-Install Guard ไม่สำเร็จ', 'error'); return; }
    _uiData = await r.json();
    uiRender();
  } catch(e) { toast('โหลดข้อมูลล้มเหลว', 'error'); }
}

function uiRender() {
  const d = _uiData;
  document.getElementById('ui-enabled').checked  = !!d.enabled;
  document.getElementById('ui-log').checked       = d.log_to_channel !== false;
  document.getElementById('ui-timeout-sec').value = d.timeout_seconds || 300;
  // radio action
  const act = d.action || 'delete';
  document.querySelectorAll('input[name="ui-action"]').forEach(r => r.checked = (r.value === act));
  // show/hide timeout row
  document.getElementById('ui-timeout-row').style.display = act === 'timeout' ? '' : 'none';
  // radio listener
  document.querySelectorAll('input[name="ui-action"]').forEach(r => {
    r.onchange = () => {
      document.getElementById('ui-timeout-row').style.display =
        document.querySelector('input[name="ui-action"]:checked')?.value === 'timeout' ? '' : 'none';
    };
  });
  // render lists
  uiRenderList('ui-app-list',  d.whitelist_apps  || [], 'app');
  uiRenderList('ui-user-list', d.whitelist_users || [], 'user');
}

function uiRenderList(containerId, items, type) {
  const el = document.getElementById(containerId);
  if (!el) return;
  el.innerHTML = items.length === 0
    ? `<div style="font-size:12px;color:var(--muted);">ยังไม่มีรายการ</div>`
    : items.map((v, i) => `
        <div style="display:flex;align-items:center;justify-content:space-between;
             background:var(--surface2);border-radius:8px;padding:6px 10px;">
          <span style="font-size:13px;font-family:monospace;">${v}</span>
          <button class="btn btn-sm" style="color:var(--danger);"
            onclick="uiRemoveItem('${type}',${i})">ลบ</button>
        </div>`).join('');
}

function uiRemoveItem(type, idx) {
  if (type === 'app')  _uiData.whitelist_apps.splice(idx, 1);
  if (type === 'user') _uiData.whitelist_users.splice(idx, 1);
  uiRenderList(type === 'app' ? 'ui-app-list' : 'ui-user-list',
               type === 'app' ? _uiData.whitelist_apps : _uiData.whitelist_users, type);
}

function uiAddApp() {
  const v = document.getElementById('ui-app-input').value.trim();
  if (!v || !/^\d+$/.test(v)) { toast('กรุณากรอก Application ID (ตัวเลขเท่านั้น)', 'error'); return; }
  if (_uiData.whitelist_apps.includes(v)) { toast('มีอยู่แล้ว', 'error'); return; }
  _uiData.whitelist_apps.push(v);
  document.getElementById('ui-app-input').value = '';
  uiRenderList('ui-app-list', _uiData.whitelist_apps, 'app');
}

function uiAddUser() {
  const v = document.getElementById('ui-user-input').value.trim();
  if (!v || !/^\d+$/.test(v)) { toast('กรุณากรอก User ID (ตัวเลขเท่านั้น)', 'error'); return; }
  if (_uiData.whitelist_users.includes(v)) { toast('มีอยู่แล้ว', 'error'); return; }
  _uiData.whitelist_users.push(v);
  document.getElementById('ui-user-input').value = '';
  uiRenderList('ui-user-list', _uiData.whitelist_users, 'user');
}

async function uiSave() {
  const act = document.querySelector('input[name="ui-action"]:checked')?.value || 'delete';
  const payload = {
    enabled:         document.getElementById('ui-enabled').checked,
    action:          act,
    timeout_seconds: parseInt(document.getElementById('ui-timeout-sec').value) || 300,
    log_to_channel:  document.getElementById('ui-log').checked,
    whitelist_apps:  _uiData.whitelist_apps  || [],
    whitelist_users: _uiData.whitelist_users || [],
  };
  try {
    const r = await fetch(`${API_BASE}/api/user-install?token=${getToken()}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const d = await r.json();
    if (d.ok) {
      _uiData = { ..._uiData, ...payload };
      toast('บันทึก User-Install Guard สำเร็จ ✅', 'success');
    } else {
      toast('บันทึกล้มเหลว: ' + (d.error || 'unknown'), 'error');
    }
  } catch(e) { toast('เกิดข้อผิดพลาด', 'error'); }
}

// ─── BUTTON RIPPLE & SVG ANIMATION ───────────────────────────────
(function(){
  function addRipple(e){
    const btn = e.currentTarget;
    const r = btn.getBoundingClientRect();
    const size = Math.max(r.width, r.height) * 1.5;
    const x = e.clientX - r.left - size/2;
    const y = e.clientY - r.top  - size/2;
    const ripple = document.createElement('span');
    ripple.className = 'btn-ripple ' + (
      btn.classList.contains('btn-primary') ? 'btn-ripple-primary' :
      btn.classList.contains('btn-success') ? 'btn-ripple-success' :
      btn.classList.contains('btn-danger')  ? 'btn-ripple-danger'  :
      'btn-ripple-default'
    );
    ripple.style.cssText = `width:${size}px;height:${size}px;left:${x}px;top:${y}px;`;
    btn.appendChild(ripple);
    ripple.addEventListener('animationend', () => ripple.remove());
  }

  // attach ripple to all .btn (and future ones via MutationObserver)
  function attachRipples(root){
    root.querySelectorAll('.btn').forEach(b => {
      if(!b.dataset.ripple){
        b.dataset.ripple = '1';
        b.addEventListener('click', addRipple);
      }
    });
  }
  document.addEventListener('DOMContentLoaded', () => attachRipples(document));
  const mo = new MutationObserver(muts => muts.forEach(m =>
    m.addedNodes.forEach(n => n.querySelectorAll && attachRipples(n))
  ));
  mo.observe(document.body || document.documentElement, {childList:true, subtree:true});
})();

// ─── THREAT DASHBOARD ─────────────────────────────────────────────
const NUKE_KEYS_TD = ['anti_ban','anti_kick','anti_ch_create','anti_ch_delete','anti_ch_update','anti_role_create','anti_role_delete','anti_role_update','anti_role_give','anti_webhook_create','anti_webhook_delete','anti_bot_add','anti_guild_update','anti_vanity','anti_prune','anti_integration'];
const RAID_KEYS_TD = ['anti_join_flood','anti_account_age','anti_no_avatar','server_lockdown'];
const SPAM_KEYS_TD = ['anti_mass_mentions','anti_text_spam','anti_link_spam','anti_att_spam','anti_emoji_spam'];

function tdSetGauge(fillId, valId, subId, on, total, color) {
  const circ = 2 * Math.PI * 32; // r=32
  const pct = total ? Math.round(on / total * 100) : 0;
  const offset = circ - (circ * pct / 100);
  const fill = document.getElementById(fillId);
  const val  = document.getElementById(valId);
  const sub  = document.getElementById(subId);
  if (fill) { fill.style.strokeDashoffset = offset; fill.style.stroke = color; }
  if (val)  val.textContent = pct + '%';
  if (sub)  sub.textContent = on + '/' + total + ' เปิด';
}

function tdSetBars(cfg) {
  const groups = [
    { label:'Anti-Nuke',  keys: NUKE_KEYS_TD,  color:'#ff4757', total:16 },
    { label:'Anti-Raid',  keys: RAID_KEYS_TD,  color:'#ffa502', total:4  },
    { label:'Anti-Spam',  keys: SPAM_KEYS_TD,  color:'#5585ff', total:5  },
  ];
  const wrap = document.getElementById('td-bars');
  if (!wrap) return;
  wrap.innerHTML = groups.map(g => {
    const on = g.keys.filter(k => (cfg[k]||{}).enabled).length;
    const pct = Math.round(on / g.total * 100);
    return `<div class="threat-level-bar">
      <div class="tlb-label">${g.label}</div>
      <div class="tlb-track"><div class="tlb-fill" style="width:${pct}%;background:${g.color};"></div></div>
      <div class="tlb-val" style="color:${g.color};">${pct}%</div>
    </div>`;
  }).join('');
}

async function loadThreatDashboard() {
  if (!CFG) return;
  const nukeOn = NUKE_KEYS_TD.filter(k => (CFG[k]||{}).enabled).length;
  const raidOn = RAID_KEYS_TD.filter(k => (CFG[k]||{}).enabled).length;
  const spamOn = SPAM_KEYS_TD.filter(k => (CFG[k]||{}).enabled).length;

  tdSetGauge('gf-nuke', 'gv-nuke', 'gs-nuke', nukeOn, 16, '#ff4757');
  tdSetGauge('gf-raid', 'gv-raid', 'gs-raid', raidOn, 4,  '#ffa502');
  tdSetGauge('gf-spam', 'gv-spam', 'gs-spam', spamOn, 5,  '#5585ff');
  tdSetBars(CFG);

  // Load stats for live counts
  try {
    const r = await fetch(`${API_BASE}/api/stats?token=${encodeURIComponent(getToken())}`);
    const d = await r.json();
    const ldEl = document.getElementById('td-lockdown-badge');
    const rmEl = document.getElementById('td-raidmode-badge');
    if (ldEl) { ldEl.className = d.in_lockdown ? 'badge badge-red' : 'badge badge-gray'; ldEl.textContent = d.in_lockdown ? 'เปิดอยู่' : 'ปิด'; }
    if (rmEl) { rmEl.className = d.raid_mode   ? 'badge badge-orange' : 'badge badge-gray'; rmEl.textContent = d.raid_mode ? 'กำลัง Raid!' : 'ปกติ'; }
    const liveLabel = document.getElementById('td-live-label');
    const liveDot   = document.getElementById('td-live-dot');
    if (d.raid_mode || d.in_lockdown) {
      if (liveLabel) liveLabel.textContent = d.raid_mode ? '⚠️ Raid Mode กำลังทำงาน' : '🔒 Server ถูก Lockdown';
      if (liveDot)   liveDot.style.background = d.raid_mode ? 'var(--warn)' : 'var(--danger)';
    } else {
      if (liveLabel) liveLabel.textContent = 'ระบบทำงานปกติ';
      if (liveDot)   liveDot.style.background = 'var(--success)';
    }
  } catch {}

  // Load logs for today counts
  try {
    const r2 = await fetch(`${API_BASE}/api/logs?token=${encodeURIComponent(getToken())}`);
    const logs = await r2.json();
    if (Array.isArray(logs)) {
      const today = new Date().toDateString();
      const todayLogs = logs.filter(l => l.timestamp && new Date(l.timestamp).toDateString() === today);
      const bans  = todayLogs.filter(l => (l.action||'').toLowerCase().includes('ban')).length;
      const kicks = todayLogs.filter(l => (l.action||'').toLowerCase().includes('kick')).length;
      const el_ban = document.getElementById('td-ban-count');
      const el_kick = document.getElementById('td-kick-count');
      const el_ev  = document.getElementById('td-event-count');
      if (el_ban)  el_ban.textContent  = bans;
      if (el_kick) el_kick.textContent = kicks;
      if (el_ev)   el_ev.textContent   = todayLogs.length;
    }
  } catch {}
}

// ─── ACTION TIMELINE ──────────────────────────────────────────────
let tlAllLogs = [];
let tlFilterActive = 'all';
let tlSearchQ = '';
let tlDisplayCount = 30;

const TL_ACTION_MAP = {
  ban: { cls:'c-danger', color:'#ff4757', label:'แบน' },
  kick: { cls:'c-warn', color:'#ffa502', label:'เตะ' },
  member_ban: { cls:'c-danger', color:'#ff4757', label:'แบน' },
  member_kick: { cls:'c-warn', color:'#ffa502', label:'เตะ' },
  message_delete: { cls:'c-info', color:'#5585ff', label:'ลบข้อความ' },
  channel_delete: { cls:'c-danger', color:'#ff4757', label:'ลบช่อง' },
  role_delete: { cls:'c-danger', color:'#ff4757', label:'ลบยศ' },
  role_create: { cls:'c-success', color:'#00c896', label:'สร้างยศ' },
  channel_create: { cls:'c-success', color:'#00c896', label:'สร้างช่อง' },
  member_update: { cls:'c-info', color:'#5585ff', label:'อัปเดตสมาชิก' },
};

function tlGetMeta(action) {
  const a = (action||'').toLowerCase();
  for (const [k, v] of Object.entries(TL_ACTION_MAP)) {
    if (a.includes(k)) return v;
  }
  return { cls:'c-gray', color:'#5a7ba0', label: action || 'event' };
}

function tlFilterLogs(logs) {
  return logs.filter(l => {
    const a = (l.action||'').toLowerCase();
    if (tlFilterActive === 'ban'  && !a.includes('ban'))  return false;
    if (tlFilterActive === 'kick' && !a.includes('kick')) return false;
    if (tlFilterActive === 'raid' && !a.includes('join') && !a.includes('raid')) return false;
    if (tlFilterActive === 'nuke' && !a.includes('channel') && !a.includes('role') && !a.includes('webhook')) return false;
    if (tlFilterActive === 'spam' && !a.includes('spam') && !a.includes('message')) return false;
    if (tlSearchQ) {
      const q = tlSearchQ.toLowerCase();
      if (!String(l.user||'').toLowerCase().includes(q) && !a.includes(q)) return false;
    }
    return true;
  });
}

function tlRender() {
  const wrap = document.getElementById('tl-list');
  const more = document.getElementById('tl-load-more');
  if (!wrap) return;
  const filtered = tlFilterLogs(tlAllLogs);
  const visible  = filtered.slice(0, tlDisplayCount);
  if (!visible.length) { wrap.innerHTML = '<div class="tl-empty">ไม่พบเหตุการณ์</div>'; if(more) more.style.display='none'; return; }
  wrap.innerHTML = visible.map((l, i) => {
    const meta = tlGetMeta(l.action);
    const dt = l.timestamp ? new Date(l.timestamp).toLocaleString('th-TH',{hour:'2-digit',minute:'2-digit',day:'numeric',month:'short'}) : '';
    const actionLabel = meta.label || (l.action||'').replace(/_/g,' ');
    return `<div class="tl-item" style="animation-delay:${Math.min(i*0.03,0.3)}s">
      <div class="tl-dot ${meta.cls}"></div>
      <div class="tl-card">
        <div class="tl-top">
          <span class="tl-badge" style="background:${meta.color}22;color:${meta.color};">${escHtml(actionLabel)}</span>
          <span class="tl-time">${dt}</span>
        </div>
        <div class="tl-desc">${escHtml(l.user||'-')}</div>
        <div class="tl-meta">เป้าหมาย: ${escHtml(String(l.target||'-'))}${l.reason&&l.reason!=='-'?' • '+escHtml(l.reason):''}</div>
      </div>
    </div>`;
  }).join('');
  if (more) more.style.display = filtered.length > tlDisplayCount ? 'inline-flex' : 'none';
}

async function loadTimeline() {
  const wrap = document.getElementById('tl-list');
  if (wrap) wrap.innerHTML = '<div class="tl-empty"><div class="loader" style="margin:auto;"></div></div>';
  try {
    const r = await fetch(`${API_BASE}/api/logs?token=${encodeURIComponent(getToken())}`);
    if (!r.ok) throw new Error();
    tlAllLogs = await r.json();
    tlDisplayCount = 30;
    tlRender();
  } catch {
    if (wrap) wrap.innerHTML = '<div class="tl-empty">โหลดไม่ได้</div>';
  }
}

function tlFilter(type) {
  tlFilterActive = type;
  tlDisplayCount = 30;
  document.querySelectorAll('.tl-filter-btn').forEach(b => b.classList.remove('active'));
  document.querySelectorAll('.tl-filter-btn').forEach(b => { if (b.getAttribute('onclick') === `tlFilter('${type}')`) b.classList.add('active'); });
  tlRender();
}

function tlSearch(q) { tlSearchQ = q; tlRender(); }
function tlLoadMore() { tlDisplayCount += 30; tlRender(); }

// ─── WEEKLY REPORT ────────────────────────────────────────────────
let wrWeekOffset = 0;
let wrChart = null;

function wrGetWeekRange(offset) {
  const now = new Date();
  const day = now.getDay();
  const startOfWeek = new Date(now);
  startOfWeek.setDate(now.getDate() - day + (offset * 7));
  startOfWeek.setHours(0,0,0,0);
  const endOfWeek = new Date(startOfWeek);
  endOfWeek.setDate(startOfWeek.getDate() + 6);
  endOfWeek.setHours(23,59,59,999);
  return { start: startOfWeek, end: endOfWeek };
}

function wrFormatRange(start, end) {
  const fmt = d => d.toLocaleDateString('th-TH', { day:'numeric', month:'short' });
  return fmt(start) + ' – ' + fmt(end);
}

function wrChangeWeek(dir) {
  wrWeekOffset += dir;
  if (wrWeekOffset > 0) wrWeekOffset = 0;
  document.getElementById('wr-next-btn').style.opacity = wrWeekOffset === 0 ? '.3' : '1';
  document.getElementById('wr-next-btn').disabled = wrWeekOffset === 0;
  loadWeeklyReport();
}

async function loadWeeklyReport() {
  const { start, end } = wrGetWeekRange(wrWeekOffset);
  const label = document.getElementById('wr-week-label');
  const title = document.getElementById('wr-title');
  const sub   = document.getElementById('wr-subtitle');
  if (label) label.textContent = wrWeekOffset === 0 ? 'สัปดาห์นี้' : wrFormatRange(start, end);
  if (title) title.textContent = wrWeekOffset === 0 ? 'สัปดาห์นี้' : 'สัปดาห์ที่ผ่านมา';

  try {
    const r = await fetch(`${API_BASE}/api/logs?token=${encodeURIComponent(getToken())}`);
    if (!r.ok) throw new Error();
    const logs = await r.json();

    const weekLogs = logs.filter(l => {
      if (!l.timestamp) return false;
      const d = new Date(l.timestamp);
      return d >= start && d <= end;
    });

    const bans   = weekLogs.filter(l => (l.action||'').toLowerCase().includes('ban')).length;
    const kicks  = weekLogs.filter(l => (l.action||'').toLowerCase().includes('kick')).length;
    const total  = weekLogs.length;
    const safePct = total > 0 ? Math.round((1 - bans/total) * 100) : 100;

    const setText = (id, val) => { const e = document.getElementById(id); if(e) e.textContent = val; };
    setText('wr-bans',   bans);
    setText('wr-kicks',  kicks);
    setText('wr-total',  total);
    setText('wr-safe-pct', safePct + '%');
    if (sub) sub.textContent = `${total} เหตุการณ์ • ${wrFormatRange(start, end)}`;

    // Top systems bar chart
    const systemCounts = {
      'Anti-Nuke':  weekLogs.filter(l => ['channel_delete','role_delete','webhook_create','ban'].some(k => (l.action||'').toLowerCase().includes(k))).length,
      'Anti-Raid':  weekLogs.filter(l => (l.action||'').toLowerCase().includes('join')).length,
      'Anti-Spam':  weekLogs.filter(l => (l.action||'').toLowerCase().includes('spam') || (l.action||'').toLowerCase().includes('message')).length,
      'Lockdown':   weekLogs.filter(l => (l.action||'').toLowerCase().includes('lock')).length,
    };
    const maxCount = Math.max(...Object.values(systemCounts), 1);
    const sysColors = { 'Anti-Nuke':'#ff4757', 'Anti-Raid':'#ffa502', 'Anti-Spam':'#5585ff', 'Lockdown':'#a855f7' };
    const topWrap = document.getElementById('wr-top-systems');
    if (topWrap) {
      topWrap.innerHTML = Object.entries(systemCounts)
        .sort((a,b)=>b[1]-a[1])
        .map(([name, count]) => `
          <div class="report-bar-row">
            <div class="report-bar-label">${name}</div>
            <div class="report-bar-track"><div class="report-bar-fill" style="width:${Math.round(count/maxCount*100)}%;background:${sysColors[name]||'#5585ff'};"></div></div>
            <div class="report-bar-count" style="color:${sysColors[name]||'#5585ff'};">${count}</div>
          </div>`).join('');
    }

    // Daily activity chart
    const days = ['อา','จ','อ','พ','พฤ','ศ','ส'];
    const dailyCounts = Array(7).fill(0);
    weekLogs.forEach(l => {
      if (l.timestamp) {
        const d = new Date(l.timestamp);
        const idx = (d.getDay());
        dailyCounts[idx]++;
      }
    });
    const ctx = document.getElementById('wr-daily-chart');
    if (ctx) {
      if (wrChart) wrChart.destroy();
      wrChart = new Chart(ctx, {
        type: 'bar',
        data: {
          labels: days,
          datasets: [{ data: dailyCounts, backgroundColor: 'rgba(85,133,255,.6)', borderRadius: 5, borderSkipped: false }]
        },
        options: {
          responsive: true, maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { ticks: { color:'#5a7ba0', font:{size:10,family:'Kanit'} }, grid:{display:false}, border:{display:false} },
            y: { ticks: { color:'#3d5478', font:{size:10,family:'Kanit'}, maxTicksLimit:4 }, grid:{color:'rgba(30,45,69,.6)'}, border:{display:false} }
          }
        }
      });
    }

  } catch {
    const sub = document.getElementById('wr-subtitle');
    if (sub) sub.textContent = 'โหลดข้อมูลไม่ได้';
  }
}


(function() {
  // หน้าที่ควรแสดงปุ่ม save ลอย
  const SAVE_PAGES = ['home','antinuke','antiraid','antispam','general','settings','whitelist'];
  let _fabVisible = false;

  function updateFab(pageId) {
    const fab = document.getElementById('fab-save');
    if (!fab) return;
    const show = SAVE_PAGES.includes(pageId);
    fab.classList.toggle('show', show);
    _fabVisible = show;
  }

  // hook เข้า goPage
  const _origGoPage = window.goPage;
  window.goPage = function(id) {
    _origGoPage(id);
    updateFab(id);
  };

  document.addEventListener('DOMContentLoaded', () => {
    const fab = document.getElementById('fab-save');
    if (fab) fab.addEventListener('click', () => saveConfig());
  });
})();

// ─── INIT ─────────────────────────────────────────────────────────
(function() {
  if (getToken()) showApp();
  // Init Lucide icons
  if (window.lucide) lucide.createIcons();
})();
</script>
<button id="fab-save" onclick="saveConfig()">
  <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M19 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11l5 5v11a2 2 0 0 1-2 2z"/><polyline points="17 21 17 13 7 13 7 21"/><polyline points="7 3 7 8 15 8"/></svg>
  บันทึก
</button>
</body>
</html>"""

async def page_index(req):
    html = DASHBOARD_HTML.replace(
        'const API_BASE = "http://localhost:8080";',
        f'const API_BASE = "{API_BASE_URL}";'
    )
    return web.Response(text=html, content_type="text/html", charset="utf-8")

# ══════════════════════════════════════════════════════════════════
#  WEB SERVER
# ══════════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════
#  WEB SERVER
#  run_web() เปิด aiohttp web server รับคำขอจาก Dashboard
#  ทุก route ต้องผ่านการ verify token ก่อน (ยกเว้น / และ /api/verify)
#
#  Routes หลัก:
#  GET  /api/verify          — ตรวจ token และคืน guild info
#  GET  /api/config          — ดึง config ปัจจุบัน
#  POST /api/config          — บันทึก config ใหม่
#  GET  /api/stats           — ข้อมูลสถิติ server
#  GET  /api/logs            — audit log ย้อนหลัง
#  POST /api/lockdown        — สั่ง lockdown/unlock จาก Dashboard
#  POST /api/advanced-manage — จัดการ advanced lockdown (restore/enable/disable)
#  GET  /api/members         — รายชื่อสมาชิก
#  GET  /api/suspicious-alerts — alerts จาก Suspicious Behavior Tracker
#  ...และอื่น ๆ ดู app.router.add_* ด้านล่าง
# ══════════════════════════════════════════════════════════════════
async def api_bie_stats(req: web.Request) -> web.Response:
    """GET /api/bie-stats — ดึง BIE scores + recent events สำหรับ Dashboard"""
    d = verify_token(req.rel_url.query.get("token", ""))
    if not d: return jres({"error":"Unauthorized"}, 401)
    gid = d["guild_id"]
    guild = bot.get_guild(gid)

    # Top threat users (score > 0.3)
    scores = bot.bie_scores.get(gid, {})
    top_threats = sorted(
        [(uid, sc) for uid, sc in scores.items() if sc > 0.3],
        key=lambda x: x[1], reverse=True
    )[:10]
    threat_list = []
    for uid, sc in top_threats:
        m = guild.get_member(uid) if guild else None
        threat_list.append({
            "user_id": uid,
            "username": str(m) if m else str(uid),
            "avatar": str(m.display_avatar.url) if m else None,
            "score": round(sc, 3),
        })

    # Recent BIE events (last 50)
    recent = list(bot.bie_events.get(gid, []))[-50:]
    event_list = [{"action": ak, "user_id": uid, "ts": ts} for ak, uid, ts in recent]

    # Hourly averages per action
    baselines = {}
    for ak in BIE_TRACKED:
        baselines[ak] = round(bie_hourly_avg(gid, ak), 2)

    return jres({
        "top_threats": threat_list,
        "recent_events": event_list,
        "baselines": baselines,
    })


async def run_web():
    app = web.Application()
    app.router.add_get("/",                           page_index)
    app.router.add_get("/dashboard",                  page_index)
    app.router.add_get("/api/verify",                 api_verify)
    app.router.add_get("/api/config",                 api_get_config)
    app.router.add_post("/api/config",                api_post_config)
    app.router.add_get("/api/stats",                  api_stats)
    app.router.add_get("/api/logs",                   api_logs)
    app.router.add_post("/api/lockdown",              api_lockdown)
    app.router.add_post("/api/advanced-manage",       api_advanced_manage)
    app.router.add_get("/api/roles",                  api_roles)
    app.router.add_get("/api/members",                api_members)
    app.router.add_get("/api/member-detail",          api_member_detail)
    app.router.add_post("/api/member-exemptions",     api_save_member_exemptions)
    app.router.add_get("/api/role-channels",          api_role_channels)
    app.router.add_get("/api/suspicious-alerts",      api_suspicious_alerts)
    app.router.add_get("/api/bie-stats",               api_bie_stats)
    app.router.add_post("/api/suspicious-alerts/read",api_mark_alert_read)
    app.router.add_get("/api/member-actions",         api_member_actions)
    app.router.add_get("/api/channels/validate",     api_channels_validate)
    app.router.add_post("/api/channels/clear",         api_channels_clear)
    app.router.add_post("/api/log-channels/create",   api_create_log_channel)
    app.router.add_post("/api/log-channels/delete",   api_delete_log_channel)
    app.router.add_post("/api/bot-action-log/create", api_create_bot_action_log)
    app.router.add_post("/api/bot-action-log/delete", api_delete_bot_action_log)
    app.router.add_post("/api/honeypot/create",       api_create_honeypot)
    app.router.add_post("/api/honeypot/delete",       api_delete_honeypot)
    app.router.add_get("/api/role-manager",            api_role_manager_get)
    app.router.add_post("/api/role-manager",           api_role_manager_post)
    app.router.add_post("/api/role-manager/auto-classify", api_role_manager_auto_classify)
    app.router.add_get("/api/user-install",                api_user_install_get)
    app.router.add_post("/api/user-install",               api_user_install_post)
    app.router.add_route("OPTIONS", "/{tail:.*}",      api_options)
    runner = web.AppRunner(app)
    await runner.setup()
    await web.TCPSite(runner, "0.0.0.0", PORT).start()
    log.info(f"🌐 Web รันที่ port {PORT}")
    while True:
        await asyncio.sleep(3600)

# ══════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════
async def main():
    await asyncio.gather(bot.start(BOT_TOKEN), run_web())

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("บอทหยุดทำงาน")
