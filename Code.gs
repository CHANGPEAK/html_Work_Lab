/**
 * Html Work's Lab - 後端 (Google Apps Script)
 *
 * 頁面：
 *   （網址本身）          公開頁面，唯讀，不需登入；可開啟程式、下載離線版
 *   （網址）?page=admin   管理者頁面，需管理員帳號密碼；擁有所有管理權限
 *                         第一次開啟時，會要求建立第一個管理員（帳號＋密碼）
 *
 * 忘記密碼時：在 Apps Script 編輯器執行 resetOnePassword（只重設單一帳號），
 *             或 resetAdmins（清除全部管理員，下次開管理者頁面重新建立）
 *
 * 雲端硬碟結構（自動建立）：
 *   <網站標題> 資料/        （改網站標題時，資料夾名稱會一起更名）
 *     manifest.json      ← 分類與排列、所有程式的摘要
 *     apps/              ← 各離線程式的 .html 程式碼
 *     meta/              ← 各程式產生的 .json 資料
 *
 * 專案檔案：Code.gs、Index.html（公開頁）、Admin.html（管理者頁）
 */

const ROOT_SUFFIX = ' 資料';                // 雲端硬碟資料夾名稱 = 網站標題 + 此字尾
const DEFAULT_TITLE = "Html Work's Lab";  // 預設標題（可在管理者頁面按「網站標題」修改）
const MAX_FAILS = 5;                      // 同一帳號連續輸錯幾次後暫時鎖定 10 分鐘

/* ---------- 路由 ---------- */
function doGet(e) {
  const p = (e && e.parameter) || {};

  // ?run=<id>：開啟已匯入的離線程式（公開，不需登入）
  if (p.run) return serveApp_(p.run);

  const isAdmin = p.page === 'admin';
  const t = HtmlService.createTemplateFromFile(isAdmin ? 'Admin' : 'Index');
  t.baseUrl = ScriptApp.getService().getUrl();
  t.siteTitle = getSiteTitle_();
  return t.evaluate()
    .setTitle(isAdmin ? '管理者頁面｜' + t.siteTitle : t.siteTitle)
    .addMetaTag('viewport', 'width=device-width, initial-scale=1')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}

function serveApp_(id) {
  const a = readManifest_().apps[id];
  if (!a || a.type !== 'offline') {
    return HtmlService.createHtmlOutput('找不到此程式，可能已被刪除。');
  }
  const html = DriveApp.getFileById(a.codeFileId).getBlob().getDataAsString('UTF-8');
  return HtmlService.createHtmlOutput(html)
    .setTitle(a.name)
    .addMetaTag('viewport', 'width=device-width, initial-scale=1')
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}

/* ---------- 管理員帳號 ---------- */
// 管理員資料存在指令碼屬性 ADMINS：{ 帳號大寫: {name, salt, hash, created} }
function hash_(pw, salt) {
  const bytes = Utilities.computeDigest(
    Utilities.DigestAlgorithm.SHA_256, salt + '|' + pw, Utilities.Charset.UTF_8);
  return bytes.map(b => ('0' + (b & 0xff).toString(16)).slice(-2)).join('');
}

function adminKey_(name) {
  return String(name || '').trim().toUpperCase();   // 帳號不分大小寫
}

function readAdmins_() {
  const props = PropertiesService.getScriptProperties();
  let a = null;
  try { a = JSON.parse(props.getProperty('ADMINS') || 'null'); } catch (err) { a = null; }
  return a || {};     // 尚未建立任何管理員時回傳空物件（會進入「首次設定」）
}

function writeAdmins_(a) {
  PropertiesService.getScriptProperties().setProperty('ADMINS', JSON.stringify(a));
}

function failKey_(key) {
  return 'fails_' + hash_(key, 'f').slice(0, 24);
}

function newToken_(key, adminRec) {
  const token = Utilities.getUuid() + Utilities.getUuid().replace(/-/g, '');
  // 憑證內記錄「帳號 + 密碼指紋」：密碼被變更或帳號被刪除時，舊憑證自動失效
  CacheService.getScriptCache().put('tok_' + token, key + '|' + adminRec.hash.slice(0, 16), 21600);
  return token;
}

// 管理員登入，成功回傳登入憑證（6 小時內有效）
function login(username, password) {
  const key = adminKey_(username);
  const cache = CacheService.getScriptCache();
  const fk = failKey_(key);
  const fails = Number(cache.get(fk) || 0);
  if (fails >= MAX_FAILS) throw new Error('嘗試次數過多，請 10 分鐘後再試');

  const admins = readAdmins_();
  if (!Object.keys(admins).length) throw new Error('尚未設定管理員，請先完成首次設定');
  const rec = admins[key];
  if (!key || !rec || hash_(String(password || ''), rec.salt) !== rec.hash) {
    cache.put(fk, String(fails + 1), 600);
    throw new Error('帳號或密碼錯誤');
  }
  cache.remove(fk);
  return newToken_(key, rec);
}

function session_(token) {
  if (!token) return null;
  const v = CacheService.getScriptCache().get('tok_' + token);
  if (!v) return null;
  const i = v.lastIndexOf('|');
  const key = v.slice(0, i), fp = v.slice(i + 1);
  const rec = readAdmins_()[key];
  if (!rec || rec.hash.slice(0, 16) !== fp) return null;
  return { key: key, rec: rec };
}

// 驗證管理員身分；失敗時丟出 AUTH，前端會回到登入畫面
function requireAuth_(token) {
  const s = session_(token);
  if (!s) throw new Error('AUTH');
  return s;
}

function logout(token) {
  CacheService.getScriptCache().remove('tok_' + token);
  return true;
}

function validUsername_(u) {
  u = String(u || '').trim();
  if (u.length < 2 || u.length > 30) throw new Error('帳號長度須為 2～30 個字元');
  if (/\s/.test(u)) throw new Error('帳號不可包含空白');
  return u;
}

function validPassword_(p) {
  p = String(p || '');
  if (p.length < 6) throw new Error('密碼至少 6 個字元');
  return p;
}

function listAdmins(token) {
  const me = requireAuth_(token);
  const all = readAdmins_();
  return Object.keys(all)
    .map(k => ({ username: all[k].name, created: all[k].created, self: k === me.key }))
    .sort((x, y) => String(x.created).localeCompare(String(y.created)));
}

function addAdmin(token, username, password) {
  requireAuth_(token);
  return withLock_(() => {
    const name = validUsername_(username);
    const pw = validPassword_(password);
    const all = readAdmins_();
    const key = adminKey_(name);
    if (all[key]) throw new Error('此帳號已存在');
    const salt = Utilities.getUuid();
    all[key] = { name: name, salt: salt, hash: hash_(pw, salt), created: new Date().toISOString() };
    writeAdmins_(all);
    return true;
  });
}

// 設定任一管理員的密碼。若改的是自己，回傳新憑證（舊憑證會失效）
function setAdminPassword(token, username, newPw) {
  const me = requireAuth_(token);
  return withLock_(() => {
    const pw = validPassword_(newPw);
    const all = readAdmins_();
    const key = adminKey_(username);
    const rec = all[key];
    if (!rec) throw new Error('找不到此管理員');
    rec.salt = Utilities.getUuid();
    rec.hash = hash_(pw, rec.salt);
    writeAdmins_(all);
    if (key === me.key) {
      CacheService.getScriptCache().remove('tok_' + token);
      return { token: newToken_(key, rec) };
    }
    return { token: null };
  });
}

function deleteAdmin(token, username) {
  const me = requireAuth_(token);
  return withLock_(() => {
    const all = readAdmins_();
    const key = adminKey_(username);
    if (!all[key]) throw new Error('找不到此管理員');
    if (key === me.key) throw new Error('不能刪除目前登入中的自己');
    if (Object.keys(all).length <= 1) throw new Error('至少要保留一位管理員');
    delete all[key];
    writeAdmins_(all);
    return true;
  });
}

/* ---------- 首次設定 ---------- */
function needSetup_() {
  return !Object.keys(readAdmins_()).length;
}

// 公開：登入畫面用來判斷要顯示「登入」還是「首次設定」
function getAuthInfo() {
  return { needSetup: needSetup_(), siteTitle: getSiteTitle_() };
}

// 公開：只有在「還沒有任何管理員」時才能使用；建立第一個管理員並直接登入
function setupFirstAdmin(username, password, siteTitle) {
  return withLock_(() => {
    if (!needSetup_()) throw new Error('已完成初始設定，請直接登入');
    const name = validUsername_(username);
    const pw = validPassword_(password);
    const salt = Utilities.getUuid();
    const rec = { name: name, salt: salt, hash: hash_(pw, salt), created: new Date().toISOString() };
    const all = {};
    all[adminKey_(name)] = rec;
    writeAdmins_(all);
    // 同時設定網站名稱（留空則使用預設）；失敗不影響管理員建立
    try { if (String(siteTitle || '').trim()) applySiteTitle_(siteTitle); } catch (err) {}
    return newToken_(adminKey_(name), rec);
  });
}

/* ---------- 忘記密碼的解決辦法（需有 Apps Script 專案編輯權限） ---------- */
// 辦法一：只重設某一位管理員的密碼
//   1. 修改下面 USERNAME 與 NEW_PASSWORD
//   2. 在 Apps Script 編輯器上方選此函式 resetOnePassword，按「執行」
//   3. 用新密碼登入後，建議立刻在管理者頁面再變更一次
function resetOnePassword() {
  const USERNAME = '在這裡填帳號';
  const NEW_PASSWORD = '在這裡填新密碼（至少 6 個字元）';

  const all = readAdmins_();
  const key = adminKey_(USERNAME);
  if (!all[key]) {
    throw new Error('找不到帳號「' + USERNAME + '」。目前的帳號有：' +
      Object.keys(all).map(k => all[k].name).join('、'));
  }
  const pw = validPassword_(NEW_PASSWORD);
  all[key].salt = Utilities.getUuid();
  all[key].hash = hash_(pw, all[key].salt);
  writeAdmins_(all);
  CacheService.getScriptCache().remove(failKey_(key));   // 同時解除「輸錯太多次」的鎖定
  Logger.log('已重設「' + all[key].name + '」的密碼');
}

// 辦法二：清除所有管理員（連帳號都忘記時用）
//   執行後，下次開啟管理者頁面（?page=admin）會再次出現「首次設定」，重新建立管理員
function resetAdmins() {
  PropertiesService.getScriptProperties().deleteProperty('ADMINS');
  Logger.log('已清除所有管理員；請開啟管理者頁面重新建立。');
}

/* ---------- 網站標題 ---------- */
function getSiteTitle_() {
  return PropertiesService.getScriptProperties().getProperty('SITE_TITLE') || DEFAULT_TITLE;
}

// 設定標題；留空代表還原為預設標題
function setSiteTitle(token, title) {
  requireAuth_(token);
  return withLock_(() => applySiteTitle_(title));
}

// 儲存標題，並把雲端硬碟資料夾一併更名；回傳目前生效的標題
function applySiteTitle_(title) {
  const t = String(title || '').trim().slice(0, 40);
  const props = PropertiesService.getScriptProperties();
  if (t) props.setProperty('SITE_TITLE', t); else props.deleteProperty('SITE_TITLE');
  const cur = getSiteTitle_();
  try { root_().setName(cur + ROOT_SUFFIX); } catch (err) { /* 資料夾更名失敗不影響標題儲存 */ }
  return cur;
}

/* ---------- 雲端硬碟輔助 ---------- */
function root_() {
  const props = PropertiesService.getScriptProperties();
  const id = props.getProperty('ROOT_ID');
  if (id) {
    try {
      const f = DriveApp.getFolderById(id);
      if (!f.isTrashed()) return f;
    } catch (err) { /* 重新建立 */ }
  }
  const f = DriveApp.createFolder(getSiteTitle_() + ROOT_SUFFIX);
  props.setProperty('ROOT_ID', f.getId());
  return f;
}

function sub_(name) {
  const r = root_();
  const it = r.getFoldersByName(name);
  return it.hasNext() ? it.next() : r.createFolder(name);
}

function manifestFile_() {
  const r = root_();
  const it = r.getFilesByName('manifest.json');
  if (it.hasNext()) return it.next();
  return r.createFile('manifest.json',
    JSON.stringify({ categories: [], unsorted: [], apps: {} }), 'application/json');
}

function readManifest_() {
  let m;
  try { m = JSON.parse(manifestFile_().getBlob().getDataAsString('UTF-8')); }
  catch (err) { m = {}; }
  m.categories = m.categories || [];
  m.unsorted = m.unsorted || [];
  m.apps = m.apps || {};
  return m;
}

function writeManifest_(m) {
  manifestFile_().setContent(JSON.stringify(m));
}

function withLock_(fn) {
  const lock = LockService.getScriptLock();
  lock.waitLock(30000);
  try { return fn(); } finally { lock.releaseLock(); }
}

function safeName_(s) {
  return String(s).replace(/[\\/:*?"<>|]/g, '_').slice(0, 80) || 'app';
}

// 標籤正規化：可傳入陣列或以逗號／頓號／換行分隔的字串
function normTags_(t) {
  const arr = Array.isArray(t) ? t : String(t || '').split(/[,，、\n]+/);
  const out = [];
  arr.forEach(x => {
    x = String(x).trim().replace(/^#/, '').slice(0, 20);
    if (x && out.indexOf(x) < 0) out.push(x);
  });
  return out.slice(0, 20);
}

function publicMeta_(a) {
  return { id: a.id, name: a.name, type: a.type, url: a.url || '', size: a.size || 0,
           created: a.created, tags: a.tags || [] };
}

function publicApps_(m) {
  const apps = {};
  Object.keys(m.apps).forEach(id => { apps[id] = publicMeta_(m.apps[id]); });
  return apps;
}

/* ---------- 公開（唯讀）函式：不需登入 ---------- */
function getPublicState() {
  const m = readManifest_();
  return { categories: m.categories, unsorted: m.unsorted, apps: publicApps_(m), siteTitle: getSiteTitle_() };
}

// 下載離線版程式：回傳名稱與完整 HTML，由瀏覽器存成檔案
function getAppHtml(id) {
  const a = readManifest_().apps[id];
  if (!a || a.type !== 'offline') throw new Error('找不到此程式，可能已被刪除');
  return {
    name: a.name,
    html: DriveApp.getFileById(a.codeFileId).getBlob().getDataAsString('UTF-8')
  };
}

/* ---------- 管理員函式：需登入 ---------- */
function getState(token) {
  const me = requireAuth_(token);
  const m = readManifest_();
  return {
    categories: m.categories,
    unsorted: m.unsorted,
    apps: publicApps_(m),
    rootUrl: root_().getUrl(),
    siteTitle: getSiteTitle_(),
    me: me.rec.name
  };
}

// 匯入離線版程式：程式碼存 apps/，產生的 json 存 meta/
function importApp(token, name, html, tags) {
  requireAuth_(token);
  return withLock_(() => {
    const id = Utilities.getUuid();
    const title = String(name || '未命名程式').slice(0, 80);
    const codeFile = sub_('apps').createFile(
      safeName_(title) + '__' + id.slice(0, 8) + '.html', html, MimeType.HTML);

    const meta = {
      id: id,
      name: title,
      type: 'offline',
      codeFileId: codeFile.getId(),
      codeFileName: codeFile.getName(),
      size: html.length,
      tags: normTags_(tags),
      created: new Date().toISOString()
    };
    const jsonFile = sub_('meta').createFile(
      safeName_(title) + '__' + id.slice(0, 8) + '.json',
      JSON.stringify(meta, null, 2), 'application/json');
    meta.jsonFileId = jsonFile.getId();

    const m = readManifest_();
    m.apps[id] = meta;
    m.unsorted.push(id);
    writeManifest_(m);
    return publicMeta_(meta);
  });
}

// 新增線上版程式（連結）
function addLink(token, name, url, tags) {
  requireAuth_(token);
  return withLock_(() => {
    url = String(url || '').trim();
    if (!/^https?:\/\//i.test(url)) throw new Error('網址必須以 http:// 或 https:// 開頭');
    let title = String(name || '').trim();
    if (!title) {
      const mt = url.match(/^https?:\/\/([^\/?#]+)/i);
      title = mt ? mt[1] : '線上程式';
    }
    const id = Utilities.getUuid();
    const meta = {
      id: id, name: title.slice(0, 80), type: 'link', url: url,
      tags: normTags_(tags),
      created: new Date().toISOString()
    };
    const jsonFile = sub_('meta').createFile(
      safeName_(title) + '__' + id.slice(0, 8) + '.json',
      JSON.stringify(meta, null, 2), 'application/json');
    meta.jsonFileId = jsonFile.getId();

    const m = readManifest_();
    m.apps[id] = meta;
    m.unsorted.push(id);
    writeManifest_(m);
    return publicMeta_(meta);
  });
}

function renameApp(token, id, name) {
  requireAuth_(token);
  return withLock_(() => {
    const m = readManifest_();
    const a = m.apps[id];
    if (!a) throw new Error('找不到此程式');
    a.name = String(name || '').trim().slice(0, 80) || a.name;
    try {
      DriveApp.getFileById(a.jsonFileId).setContent(JSON.stringify(a, null, 2));
    } catch (err) { /* json 遺失時略過 */ }
    writeManifest_(m);
    return a.name;
  });
}

// 設定某個程式的標籤（同步更新 manifest 與該程式的 json）
function setTags(token, id, tags) {
  requireAuth_(token);
  return withLock_(() => {
    const m = readManifest_();
    const a = m.apps[id];
    if (!a) throw new Error('找不到此程式');
    a.tags = normTags_(tags);
    try {
      DriveApp.getFileById(a.jsonFileId).setContent(JSON.stringify(a, null, 2));
    } catch (err) { /* json 遺失時略過 */ }
    writeManifest_(m);
    return a.tags;
  });
}

function deleteApp(token, id) {
  requireAuth_(token);
  return withLock_(() => {
    const m = readManifest_();
    const a = m.apps[id];
    if (a) {
      [a.codeFileId, a.jsonFileId].forEach(fid => {
        if (!fid) return;
        try { DriveApp.getFileById(fid).setTrashed(true); } catch (err) {}
      });
      delete m.apps[id];
    }
    m.unsorted = m.unsorted.filter(x => x !== id);
    m.categories.forEach(c => { c.items = c.items.filter(x => x !== id); });
    writeManifest_(m);
    return true;
  });
}

// 儲存分類與排列
function saveLayout(token, layout) {
  requireAuth_(token);
  return withLock_(() => {
    const m = readManifest_();
    const seen = {};
    const clean = ids => (ids || []).filter(id => m.apps[id] && !seen[id] && (seen[id] = true));

    m.categories = (layout.categories || []).map(c => ({
      id: String(c.id),
      name: String(c.name || '未命名分類').slice(0, 60),
      items: clean(c.items)
    }));
    const un = clean(layout.unsorted);
    Object.keys(m.apps).forEach(id => { if (!seen[id]) { un.push(id); seen[id] = true; } });
    m.unsorted = un;
    writeManifest_(m);
    return true;
  });
}
