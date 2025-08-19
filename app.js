// ========= Utilities =========
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const enc = new TextEncoder();
const dec = new TextDecoder();

function base32ToBytes(s) {
    let bits = "", out = [];
    s = (s || "").replace(/[\s-]/g, "").replace(/=+$/,"").toUpperCase();
    for (const ch of s) {
    const v = B32.indexOf(ch);
    if (v < 0) continue;
    bits += v.toString(2).padStart(5, "0");
    }
    for (let i = 0; i + 8 <= bits.length; i += 8) {
    out.push(parseInt(bits.slice(i, i+8), 2));
    }
    return new Uint8Array(out);
}
function ab2b64(buf) {
    const bytes = new Uint8Array(buf);
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
}
function b642ab(b64) {
    const bin = atob(b64);
    const len = bin.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
}

async function hmacSha1(keyBytes, counter) {
    const key = await crypto.subtle.importKey("raw", keyBytes, {name: "HMAC", hash: "SHA-1"}, false, ["sign"]);
    const buf = new ArrayBuffer(8);
    const view = new DataView(buf);
    // counter is 64-bit big-endian; we only set low 32 for typical TOTP
    view.setUint32(4, counter);
    const sig = await crypto.subtle.sign("HMAC", key, buf);
    return new Uint8Array(sig);
}

async function totp(secretB32) {
    const key = base32ToBytes(secretB32);
    const epoch = Math.floor(Date.now() / 1000);
    const counter = Math.floor(epoch / 30);
    const hmac = await hmacSha1(key, counter);
    const offset = hmac[hmac.length - 1] & 0x0f;
    const bin =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);
    return (bin % 1e6).toString().padStart(6, "0");
}

function nowSecsLeft() { return 30 - (Math.floor(Date.now()/1000) % 30); }

// ========= Storage =========
function getAccounts() {
    return JSON.parse(localStorage.getItem("accounts") || "[]");
}
function setAccounts(a) {
    localStorage.setItem("accounts", JSON.stringify(a));
    render();
}

// ========= UI: render/update =========
function render() {
    const grid = document.getElementById("grid");
    const empty = document.getElementById("empty");
    const accounts = getAccounts();
    grid.innerHTML = "";
    empty.style.display = accounts.length ? "none" : "block";

    accounts.forEach((acc, i) => {
    const card = document.createElement("div");
    card.className = "card";
    card.innerHTML = `
        <div class="card-head">
        <div class="name">${escapeHtml(acc.name || "Account")}</div>
        <div class="actions">
            <button class="icon-btn" title="Edit" onclick="openEdit(${i})">✎</button>
            <button class="icon-btn" title="Delete" onclick="removeAccount(${i})">🗑</button>
        </div>
        </div>
        <div class="code" id="code-${i}">------</div>
        <div class="row">
        <div class="timer" id="timer-${i}">--</div>
        <div class="timer">${maskSecret(acc.secret)}</div>
        </div>
        <div class="progress"><div class="bar" id="bar-${i}"></div></div>
    `;
    grid.appendChild(card);
    });
}

function maskSecret(s) {
    if (!s) return "";
    const xs = s.replace(/\s+/g, "");
    if (xs.length <= 6) return "••••";
    return xs.slice(0, 3) + "••••" + xs.slice(-3);
}
function escapeHtml(str="") {
    return str.replace(/[&<>"']/g, c =>
    ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])
    );
}

async function tick() {
    const accounts = getAccounts();
    const secs = nowSecsLeft();
    for (let i = 0; i < accounts.length; i++) {
    const codeEl = document.getElementById(`code-${i}`);
    const timEl  = document.getElementById(`timer-${i}`);
    const barEl  = document.getElementById(`bar-${i}`);
    if (!codeEl || !timEl || !barEl) continue;
    try {
        codeEl.textContent = await totp(accounts[i].secret);
    } catch {
        codeEl.textContent = "ERROR";
    }
    timEl.textContent = `Refreshes in ${secs}s`;
    barEl.style.transform = `scaleX(${secs/30})`;
    }
}

setInterval(tick, 1000);

// ========= Add/Edit/Delete =========
let editingIndex = null;

function openAdd() {
    editingIndex = null;
    document.getElementById("accountModalTitle").textContent = "Add Account";
    document.getElementById("accountName").value = "";
    document.getElementById("accountSecret").value = "";
    openModal("accountModal");
}
function openEdit(index) {
    const acc = getAccounts()[index];
    if (!acc) return;
    editingIndex = index;
    document.getElementById("accountModalTitle").textContent = "Edit Account";
    document.getElementById("accountName").value = acc.name || "";
    document.getElementById("accountSecret").value = acc.secret || "";
    openModal("accountModal");
}
function saveAccount() {
    const name = document.getElementById("accountName").value.trim();
    const secret = document.getElementById("accountSecret").value.trim();
    if (!name || !secret) { alert("Name and Base32 secret are required."); return; }
    if (!/^[A-Z2-7= ]+$/i.test(secret)) {
    if (!confirm("Secret has non-Base32 characters. Save anyway?")) return;
    }
    const accounts = getAccounts();
    if (editingIndex === null) accounts.push({ name, secret });
    else accounts[editingIndex] = { name, secret };
    setAccounts(accounts);
    closeModal("accountModal");
}
function removeAccount(index) {
    const acc = getAccounts()[index];
    if (!acc) return;
    if (!confirm(`Delete “${acc.name}”? This cannot be undone.`)) return;
    const accounts = getAccounts();
    accounts.splice(index, 1);
    setAccounts(accounts);
}

// ========= Modals =========
function openModal(id) { document.getElementById(id).classList.add("active"); }
function closeModal(id) { document.getElementById(id).classList.remove("active"); }

["accountModal","exportModal","importModal"].forEach(id => {
    document.getElementById(id).addEventListener("click", (e) => {
    if (e.target.id === id) closeModal(id);
    });
});

// ========= Export (Encrypted) =========
async function exportEncrypted(password) {
    const data = { accounts: getAccounts() };
    const plaintext = enc.encode(JSON.stringify(data));

    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv   = crypto.getRandomValues(new Uint8Array(12));
    const iter = 200_000;

    const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt","decrypt"]
    );
    const ctBuf = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);

    const payload = {
    v: 1,
    alg: "AES-GCM",
    kdf: "PBKDF2",
    iter,
    salt: ab2b64(salt.buffer),
    iv:   ab2b64(iv.buffer),
    ct:   ab2b64(ctBuf),
    created: new Date().toISOString()
    };

    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const d = new Date();
    const y = d.getFullYear(), m = String(d.getMonth()+1).padStart(2,"0"), day = String(d.getDate()).padStart(2,"0");
    a.href = url;
    a.download = `AuthLite-backup-${y}${m}${day}.json`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
}

// ========= Import (Encrypted) =========
async function importEncrypted(payload, password) {
    if (!payload || payload.v !== 1 || !payload.ct || !payload.salt || !payload.iv) {
    throw new Error("Invalid backup file.");
    }
    const salt = new Uint8Array(b642ab(payload.salt));
    const iv   = new Uint8Array(b642ab(payload.iv));
    const ct   = b642ab(payload.ct);
    const iter = payload.iter || 200_000;

    const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
    const key = await crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt","decrypt"]
    );

    const ptBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
    const txt = dec.decode(ptBuf);
    const obj = JSON.parse(txt);

    if (!obj || !Array.isArray(obj.accounts)) throw new Error("Backup did not contain accounts.");
    const current = getAccounts();
    const incoming = obj.accounts;
    const merged = [...current];

    incoming.forEach(acc => {
    const idx = merged.findIndex(a => a.name === acc.name);
    if (idx === -1) merged.push(acc);
    else {
        const choice = confirm(`Account "${acc.name}" exists. Replace it with imported version? OK=Replace, Cancel=Skip`);
        if (choice) merged[idx] = acc;
    }
    });
    setAccounts(merged);
}

document.getElementById("addBtn").addEventListener("click", openAdd);
document.getElementById("accountSave").addEventListener("click", saveAccount);
document.getElementById("accountCancel").addEventListener("click", () => closeModal("accountModal"));

// Export
document.getElementById("exportBtn").addEventListener("click", () => openModal("exportModal"));
document.getElementById("exportCancel").addEventListener("click", () => closeModal("exportModal"));
document.getElementById("exportGo").addEventListener("click", async () => {
    const p1 = document.getElementById("exportPass1").value;
    const p2 = document.getElementById("exportPass2").value;
    if (!p1 || !p2) { alert("Enter and confirm a password."); return; }
    if (p1 !== p2) { alert("Passwords do not match."); return; }
    try {
    await exportEncrypted(p1);
    closeModal("exportModal");
    document.getElementById("exportPass1").value = "";
    document.getElementById("exportPass2").value = "";
    } catch (e) {
    alert("Export failed: " + e.message);
    }
});

// Import
const fileInput = document.getElementById("fileInput");
document.getElementById("importBtn").addEventListener("click", () => openModal("importModal"));
document.getElementById("importCancel").addEventListener("click", () => closeModal("importModal"));
document.getElementById("chooseFile").addEventListener("click", () => fileInput.click());
fileInput.addEventListener("change", () => {
    const f = fileInput.files?.[0];
    document.getElementById("importFileName").value = f ? f.name : "";
});
document.getElementById("importGo").addEventListener("click", async () => {
    const f = fileInput.files?.[0];
    const pass = document.getElementById("importPass").value;
    if (!f) { alert("Choose a backup file."); return; }
    if (!pass) { alert("Enter the backup password."); return; }
    try {
    const text = await f.text();
    const payload = JSON.parse(text);
    await importEncrypted(payload, pass);
    closeModal("importModal");
    document.getElementById("importPass").value = "";
    document.getElementById("importFileName").value = "";
    fileInput.value = "";
    } catch (e) {
    alert("Import failed: " + (e.message || e));
    }
});
render();
tick();