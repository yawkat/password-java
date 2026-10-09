// Emergency web client: read-only, same protocol as the apps (see SPEC.md). Everything runs in the browser; the
// server only sees signed requests.
"use strict";

(() => {
    const VERSION = 1;
    // fixed by the protocol version, never read from the server (KeyMaterial.java)
    const ARGON2 = {memorySize: 64 * 1024, iterations: 4, parallelism: 4, hashLength: 32};
    const SALT_LENGTH = 32;
    const MAGIC = [0x50, 0x57, 0x44, 0x42]; // "PWDB"
    const INSTALL_SALT_OFFSET = 5;
    const BLOB_SALT_OFFSET = INSTALL_SALT_OFFSET + SALT_LENGTH;
    const NONCE_OFFSET = BLOB_SALT_OFFSET + 32;
    const HEADER_LENGTH = NONCE_OFFSET + 12;
    const TAG_LENGTH = 16;
    // PKCS#8 encoding of an Ed25519 private key, followed by the 32-byte seed. WebCrypto can't import a raw seed.
    const ED25519_PKCS8_PREFIX = fromHex("302e020100300506032b657004220420");

    // The two vaults of SPEC.md: their paths (relative to the page) and the path that the signature covers
    const VAULTS = {
        passwords: {
            prefix: "", signedPath: "/db", passwordLabel: "Master password",
            empty: "The server has no password database yet",
        },
        totp: {
            prefix: "totp/", signedPath: "/totp/db", passwordLabel: "Backup password (18-028)",
            empty: "The server has no 2FA codes yet",
        },
    };
    // HMAC of a TOTP account (model/OtpAlgorithm.java)
    const HMAC_HASHES = {SHA1: "SHA-1", SHA256: "SHA-256", SHA512: "SHA-512"};
    const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    const LOCK_AFTER_MILLIS = 5 * 60 * 1000;
    const CLEAR_CLIPBOARD_AFTER_MILLIS = 30 * 1000;
    const TIMEOUT_MILLIS = 60 * 1000;

    const encoder = new TextEncoder();

    function fromHex(hex) {
        const out = new Uint8Array(hex.length / 2);
        for (let i = 0; i < out.length; i++) {
            out[i] = parseInt(hex.substr(2 * i, 2), 16);
        }
        return out;
    }

    function toHex(bytes) {
        return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
    }

    function concat(a, b) {
        const out = new Uint8Array(a.length + b.length);
        out.set(a);
        out.set(b, a.length);
        return out;
    }

    function equal(a, b) {
        return a.length === b.length && a.every((v, i) => v === b[i]);
    }

    async function hkdf(ikm, salt, info) {
        const key = await crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
        // an empty salt is the same as none: HMAC pads the key with zeros either way
        const bits = await crypto.subtle.deriveBits(
            {name: "HKDF", hash: "SHA-256", salt, info: encoder.encode(info)}, key, 256);
        return new Uint8Array(bits);
    }

    async function deriveKeys(password, installSalt) {
        const passwordBytes = encoder.encode(password);
        let root;
        try {
            root = await hashwasm.argon2id({...ARGON2, password: passwordBytes, salt: installSalt, outputType: "binary"});
        } finally {
            passwordBytes.fill(0);
        }
        const seed = await hkdf(root, new Uint8Array(0), "at.yawk.password/v1/auth");
        const pkcs8 = concat(ED25519_PKCS8_PREFIX, seed);
        seed.fill(0);
        try {
            const authKey = await crypto.subtle.importKey("pkcs8", pkcs8, {name: "Ed25519"}, false, ["sign"]);
            return {installSalt, root, authKey};
        } catch (e) {
            root.fill(0);
            throw new Error("This browser does not support Ed25519 signatures, try a current Firefox, Chrome or Safari");
        } finally {
            pkcs8.fill(0);
        }
    }

    function wipeKeys(keys) {
        keys.root.fill(0);
    }

    // The signed request of SPEC.md, "Authentication of /db"
    async function authHeader(keys, timestamp, method, path, body) {
        const nonce = toHex(crypto.getRandomValues(new Uint8Array(16)));
        const bodyHash = toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", body)));
        const input = `at.yawk.password/v1/request\n${timestamp}\n${nonce}\n${method}\n${path}\n${bodyHash}\n`;
        const signature = await crypto.subtle.sign("Ed25519", keys.authKey, encoder.encode(input));
        return `${timestamp} ${nonce} ${toHex(new Uint8Array(signature))}`;
    }

    function httpError(what, response) {
        switch (response.status) {
            case 403:
                return new Error("Wrong password");
            case 429:
                return new Error("Too many failed attempts, the server refuses requests for a while. Try again later.");
            default:
                return new Error(`${what}: HTTP ${response.status}`);
        }
    }

    async function request(url, init) {
        // relative, so that the page also works below a path prefix of a reverse proxy. The timeout also covers
        // reading the body.
        return fetch(url, {...init, cache: "no-store", redirect: "error", signal: AbortSignal.timeout(TIMEOUT_MILLIS)});
    }

    async function fetchSalt(vault) {
        const response = await request(vault.prefix + "salt");
        if (response.status === 404) {
            throw new Error("This vault is not registered yet: there is nothing to open");
        }
        if (!response.ok) {
            throw httpError("Could not fetch the salt", response);
        }
        const body = new Uint8Array(await response.arrayBuffer());
        if (body.length !== 1 + SALT_LENGTH) {
            throw new Error("Invalid salt response");
        }
        if (body[0] !== VERSION) {
            throw new Error(`Unsupported protocol version ${body[0]}`);
        }
        return body.slice(1);
    }

    // returns the blob and the offset of the server's clock, which the TOTP codes need as well
    async function fetchDatabase(keys, vault) {
        const empty = new Uint8Array(0);
        let clockOffset = 0;
        for (let attempt = 0; ; attempt++) {
            const header = await authHeader(keys, Date.now() + clockOffset, "GET", vault.signedPath, empty);
            const response = await request(vault.prefix + "db", {headers: {"X-Auth": header}});
            const serverDate = Date.parse(response.headers.get("Date") ?? "");
            if (response.status === 401 && attempt === 0 && !Number.isNaN(serverDate)) {
                // our clock is off, retry once with the server's
                clockOffset = serverDate - Date.now();
                continue;
            }
            if (response.status === 401) {
                throw new Error("The server rejected the request time, is this device's clock wrong?");
            }
            if (response.status === 404) {
                throw new Error(vault.empty);
            }
            if (!response.ok) {
                throw httpError("Could not fetch the database", response);
            }
            return {blob: new Uint8Array(await response.arrayBuffer()), clockOffset};
        }
    }

    // The blob format of SPEC.md, "Encrypted blob"
    async function decrypt(keys, blob) {
        if (blob.length < HEADER_LENGTH + TAG_LENGTH || !equal(blob.subarray(0, 4), MAGIC)) {
            throw new Error("Invalid database: bad header");
        }
        if (blob[4] !== VERSION) {
            throw new Error(`Invalid database: unsupported version ${blob[4]}`);
        }
        if (!equal(blob.subarray(INSTALL_SALT_OFFSET, BLOB_SALT_OFFSET), keys.installSalt)) {
            throw new Error("Invalid database: different install salt");
        }
        const keyBytes = await hkdf(keys.root, blob.subarray(BLOB_SALT_OFFSET, NONCE_OFFSET),
                                    "at.yawk.password/v1/container");
        let key;
        try {
            key = await crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, ["decrypt"]);
        } finally {
            keyBytes.fill(0);
        }
        let plaintext;
        try {
            plaintext = new Uint8Array(await crypto.subtle.decrypt(
                {
                    name: "AES-GCM",
                    iv: blob.subarray(NONCE_OFFSET, HEADER_LENGTH),
                    additionalData: blob.subarray(0, HEADER_LENGTH),
                    tagLength: TAG_LENGTH * 8,
                },
                key, blob.subarray(HEADER_LENGTH)));
        } catch (e) {
            // the server accepted our signature, so the password is right: the blob is broken
            throw new Error("Could not decrypt the database");
        }
        try {
            const length = plaintext.length < 4 ? -1 : new DataView(plaintext.buffer).getUint32(0);
            if (length < 0 || length > plaintext.length - 4) {
                throw new Error("Invalid database: bad length");
            }
            return JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode(plaintext.subarray(4, 4 + length))).data;
        } finally {
            plaintext.fill(0);
        }
    }

    // like the apps, accept missing fields and scalars other than strings
    function passwordEntries(data) {
        return (data?.passwords ?? []).map(entry => ({
            name: String(entry?.name ?? ""),
            value: String(entry?.value ?? ""),
        }));
    }

    // Base32 of RFC 4648, exactly as lenient as Base32.java: ASCII case, spaces and dashes are ignored, and padding at
    // the end. Anything else is invalid, so that the apps and this page agree about every secret.
    function base32Decode(text) {
        let clean = "";
        let padding = false;
        for (const c of text) {
            if (c === " " || c === "-") {
                continue;
            }
            if (c === "=") {
                padding = true;
                continue;
            }
            const upper = c >= "a" && c <= "z" ? c.toUpperCase() : c;
            if (padding || !BASE32_ALPHABET.includes(upper)) {
                return null;
            }
            clean += upper;
        }
        const out = [];
        let buffer = 0;
        let bits = 0;
        for (const c of clean) {
            const value = BASE32_ALPHABET.indexOf(c);
            buffer = (buffer << 5 | value) & 0xffff;
            bits += 5;
            if (bits >= 8) {
                bits -= 8;
                out.push(buffer >> bits & 0xff);
            }
        }
        return [1, 3, 6].includes(clean.length % 8) ? null : new Uint8Array(out);
    }

    // A field of an account as OtpAccount.java reads it: missing gives the default, an explicit null stays null (so
    // that an account the apps call invalid is invalid here as well)
    function field(account, name, defaultValue) {
        return Object.hasOwn(account, name) ? account[name] : defaultValue;
    }

    // The accounts of the 2FA vault, each with its secret imported as a (non-extractable) HMAC key, or without a key
    // if it can't generate codes (Totp.check). One bad account never hides the others.
    async function otpAccounts(data) {
        const accounts = (data?.accounts ?? []).filter(account => account !== null && typeof account === "object");
        return Promise.all(accounts.map(async account => {
            const result = {
                issuer: String(account.issuer ?? ""),
                label: String(account.label ?? ""),
                digits: Number(field(account, "digits", 6)),
                period: Number(field(account, "period", 30)),
                backupCodes: String(account.backupCodes ?? ""),
                key: null,
            };
            const algorithm = field(account, "algorithm", "SHA1");
            const hash = typeof algorithm === "string" && Object.hasOwn(HMAC_HASHES, algorithm) ?
                HMAC_HASHES[algorithm] : null;
            const secret = typeof account.secret === "string" ? base32Decode(account.secret) : null;
            try {
                if (field(account, "type", "totp") === "totp" && hash && secret && secret.length > 0 &&
                    Number.isInteger(result.digits) && result.digits >= 6 && result.digits <= 10 &&
                    Number.isInteger(result.period) && result.period > 0) {
                    result.key = await crypto.subtle.importKey("raw", secret, {name: "HMAC", hash}, false, ["sign"]);
                }
            } catch (e) {
                // shown as "invalid"
            } finally {
                secret?.fill(0);
            }
            return result;
        }));
    }

    // RFC 6238, like Totp.java: HOTP of the number of periods since the epoch
    async function totp(account, unixMillis) {
        const counter = Math.floor(unixMillis / 1000 / account.period);
        const message = new Uint8Array(8);
        new DataView(message.buffer).setBigUint64(0, BigInt(counter));
        const hash = new Uint8Array(await crypto.subtle.sign("HMAC", account.key, message));
        const offset = hash[hash.length - 1] & 0xf;
        const binary = ((hash[offset] & 0x7f) << 24 | hash[offset + 1] << 16 | hash[offset + 2] << 8 |
            hash[offset + 3]) >>> 0;
        return String(binary % 10 ** account.digits).padStart(account.digits, "0");
    }

    async function unlock(password, vault, onProgress) {
        onProgress("Fetching salt…");
        const installSalt = await fetchSalt(vault);
        onProgress("Deriving keys, this can take a while on a slow device…");
        // let the message render: the key derivation blocks this thread
        await new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 0)));
        const keys = await deriveKeys(password, installSalt);
        try {
            onProgress("Fetching database…");
            const {blob, clockOffset} = await fetchDatabase(keys, vault);
            onProgress("Decrypting…");
            const data = await decrypt(keys, blob);
            return {
                loaded: vault === VAULTS.totp ? await otpAccounts(data) : passwordEntries(data),
                clockOffset,
            };
        } finally {
            wipeKeys(keys);
        }
    }

    // ---- UI ----

    const $ = id => document.getElementById(id);

    // the unlocked entries or 2FA accounts, null while locked
    let entries = null;
    let codeTimer = null;
    // the server's clock minus ours: the codes follow the server's clock, like the signed requests
    let clockOffset = 0;
    let updatingCodes = false;
    // incremented by lock(), so that an unlock that was running meanwhile doesn't show its result
    let generation = 0;
    let lastActivity = 0;
    let lockTimer = null;
    let clipboardTimer = null;
    // a clear that failed because the page had no focus, retried when it gets it back
    let clipboardClearPending = false;

    // Like PasswordStore.firstLine: the password ends at the first \n or \r
    function firstLine(value) {
        return value.split(/[\r\n]/, 1)[0];
    }

    function notes(value) {
        const match = /\r\n|\r|\n/.exec(value);
        return match ? value.substring(match.index + match[0].length) : "";
    }

    async function copy(text) {
        try {
            await navigator.clipboard.writeText(text);
        } catch (e) {
            $("entries-status").textContent = "Could not copy: " + e.message;
            return;
        }
        $("entries-status").textContent =
            "Copied. The clipboard is cleared in 30 seconds: keep this page open until then.";
        clipboardClearPending = false;
        clearTimeout(clipboardTimer);
        clipboardTimer = setTimeout(clearClipboard, CLEAR_CLIPBOARD_AFTER_MILLIS);
    }

    function clearClipboard() {
        clearTimeout(clipboardTimer);
        clipboardTimer = null;
        clipboardClearPending = true;
        $("entries-status").textContent = "";
        // Browsers only allow this while the page has focus, else retry on focus. A page can't read the clipboard
        // without asking, so unlike the apps this can't check that it still holds the password.
        navigator.clipboard.writeText("").then(() => clipboardClearPending = false, () => {});
    }

    function renderEntry(entry) {
        const item = document.createElement("li");
        item.dataset.name = entry.name.toLowerCase();
        const details = document.createElement("details");
        const summary = document.createElement("summary");
        summary.textContent = entry.name;
        details.append(summary);

        const password = firstLine(entry.value);
        const passwordRow = document.createElement("div");
        passwordRow.className = "password-row";
        const passwordText = document.createElement("code");
        passwordText.className = "password";
        passwordText.textContent = "••••••••";
        const show = document.createElement("button");
        show.type = "button";
        show.textContent = "Show";
        show.addEventListener("click", () => {
            const shown = show.textContent === "Hide";
            passwordText.textContent = shown ? "••••••••" : password;
            show.textContent = shown ? "Show" : "Hide";
        });
        const copyButton = document.createElement("button");
        copyButton.type = "button";
        copyButton.textContent = "Copy";
        copyButton.addEventListener("click", () => copy(password));
        passwordRow.append(passwordText, show, copyButton);
        details.append(passwordRow);

        const rest = notes(entry.value);
        if (rest) {
            const pre = document.createElement("pre");
            pre.textContent = rest;
            details.append(pre);
        }
        item.append(details);
        return item;
    }

    function selectedVault() {
        return VAULTS[document.querySelector("input[name=vault]:checked")?.value] ?? VAULTS.passwords;
    }

    function formatCode(code) {
        const split = Math.floor(code.length / 2);
        return code.substring(0, split) + " " + code.substring(split);
    }

    // A 2FA account: its name and current code, which updateCodes keeps current, and its backup codes behind "Show"
    function renderAccount(account) {
        const item = document.createElement("li");
        const title = account.issuer || account.label || "(unnamed)";
        item.dataset.name = (account.issuer + " " + account.label).toLowerCase();
        const details = document.createElement("details");
        const summary = document.createElement("summary");
        summary.className = "otp-summary";
        summary.textContent = account.issuer && account.label ? `${title} · ${account.label}` : title;
        details.append(summary);

        const codeRow = document.createElement("div");
        codeRow.className = "password-row";
        const codeText = document.createElement("code");
        codeText.className = "password otp-code";
        const countdown = document.createElement("span");
        countdown.className = "countdown";
        const copyButton = document.createElement("button");
        copyButton.type = "button";
        copyButton.textContent = "Copy";
        copyButton.disabled = account.key === null;
        // the current code at the time of the click, not the one shown
        copyButton.addEventListener("click", async () => copy(await totp(account, Date.now() + clockOffset)));
        codeRow.append(codeText, countdown, copyButton);
        // shown in the summary as well, so that a code can be read without opening the account
        const summaryCode = document.createElement("code");
        summaryCode.className = "summary-code";
        summary.append(summaryCode);
        details.append(codeRow);
        item.otp = {account, codeText, countdown, summaryCode, counter: null};

        if (account.backupCodes) {
            const backupRow = document.createElement("div");
            backupRow.className = "password-row";
            const label = document.createElement("span");
            label.className = "password";
            label.textContent = "Backup codes";
            const pre = document.createElement("pre");
            pre.hidden = true;
            pre.textContent = account.backupCodes;
            const show = document.createElement("button");
            show.type = "button";
            show.textContent = "Show";
            show.addEventListener("click", () => {
                pre.hidden = !pre.hidden;
                show.textContent = pre.hidden ? "Show" : "Hide";
            });
            backupRow.append(label, show);
            details.append(backupRow, pre);
        }
        item.append(details);
        return item;
    }

    // Show the current code and the time left of every 2FA account, computing a code only when it changes. The codes
    // are computed together; a tick that comes while the last one still computes is skipped.
    async function updateCodes() {
        if (updatingCodes) {
            return;
        }
        updatingCodes = true;
        try {
            const started = generation;
            const now = Date.now() + clockOffset;
            const changed = [];
            for (const item of $("entry-list").children) {
                const otp = item.otp;
                if (!otp) {
                    continue;
                }
                if (otp.account.key === null) {
                    otp.codeText.textContent = otp.summaryCode.textContent = "invalid";
                    continue;
                }
                const periodMillis = otp.account.period * 1000;
                otp.countdown.textContent = `${Math.ceil((periodMillis - now % periodMillis) / 1000)}s`;
                const counter = Math.floor(now / periodMillis);
                if (counter !== otp.counter) {
                    changed.push(totp(otp.account, now).then(code => ({otp, counter, code})));
                }
            }
            for (const {otp, counter, code} of await Promise.all(changed)) {
                if (generation !== started) {
                    return;
                }
                otp.counter = counter;
                otp.codeText.textContent = otp.summaryCode.textContent = formatCode(code);
            }
        } finally {
            updatingCodes = false;
        }
    }

    function filterEntries() {
        const query = $("search").value.trim().toLowerCase();
        for (const item of $("entry-list").children) {
            item.hidden = !item.dataset.name.includes(query);
        }
    }

    function showEntries({loaded, clockOffset: offset}, vault) {
        entries = loaded;
        clockOffset = offset;
        $("password").value = "";
        $("status").textContent = "";
        $("unlock").hidden = true;
        $("entries").hidden = false;
        $("search").value = "";
        if (vault === VAULTS.totp) {
            $("entry-list").replaceChildren(...entries.map(renderAccount));
            updateCodes();
            codeTimer = setInterval(updateCodes, 1000);
        } else {
            $("entry-list").replaceChildren(...entries.map(renderEntry));
        }
        $("search").focus();
        lastActivity = Date.now();
        lockTimer = setTimeout(checkIdle, LOCK_AFTER_MILLIS);
    }

    function lock(reason) {
        generation++;
        // drops the 2FA keys with the list items
        entries = null;
        clearInterval(codeTimer);
        codeTimer = null;
        clearTimeout(lockTimer);
        if (clipboardTimer !== null) {
            clearClipboard();
        }
        $("entry-list").replaceChildren();
        $("search").value = "";
        $("entries").hidden = true;
        $("unlock").hidden = false;
        $("status").textContent = reason ?? "";
        $("status").classList.remove("error");
        $("unlock-button").disabled = false;
        setVaultChoiceEnabled(true);
        $("password").value = "";
        $("password").focus();
    }

    // Timers don't run while the device sleeps or a mobile browser freezes the tab, so this also runs when the page
    // becomes visible again. Otherwise the timer reschedules itself until lastActivity is old enough.
    function checkIdle() {
        if (entries !== null && Date.now() - lastActivity >= LOCK_AFTER_MILLIS) {
            lock("Locked after five minutes without activity");
        } else if (entries !== null) {
            clearTimeout(lockTimer);
            lockTimer = setTimeout(checkIdle, LOCK_AFTER_MILLIS - (Date.now() - lastActivity));
        }
    }

    function init() {
        $("unlock-button").addEventListener("click", submit);
        $("password").addEventListener("keydown", event => {
            if (event.key === "Enter") {
                submit();
            }
        });
        async function submit() {
            const button = $("unlock-button");
            if (button.disabled || $("password").value === "") {
                return;
            }
            const started = generation;
            const vault = selectedVault();
            button.disabled = true;
            setVaultChoiceEnabled(false);
            $("status").classList.remove("error");
            try {
                const loaded = await unlock($("password").value, vault, text => {
                    if (generation === started) {
                        $("status").textContent = text;
                    }
                });
                if (generation === started) {
                    showEntries(loaded, vault);
                }
            } catch (e) {
                if (generation === started) {
                    $("status").textContent = e.message;
                    $("status").classList.add("error");
                }
            } finally {
                if (generation === started) {
                    button.disabled = false;
                    setVaultChoiceEnabled(true);
                }
            }
        }
        $("search").addEventListener("input", filterEntries);
        for (const radio of document.querySelectorAll("input[name=vault]")) {
            radio.addEventListener("change", updatePasswordLabel);
        }
        // a reload may restore the other choice
        updatePasswordLabel();
        $("lock-button").addEventListener("click", () => lock());
        for (const type of ["pointerdown", "keydown", "scroll"]) {
            document.addEventListener(type, () => lastActivity = Date.now(), {passive: true});
        }
        document.addEventListener("visibilitychange", checkIdle);
        window.addEventListener("pageshow", checkIdle);
        window.addEventListener("focus", () => {
            checkIdle();
            if (clipboardClearPending) {
                clearClipboard();
            }
        });
        // don't leave the entries in the back-forward cache
        window.addEventListener("pagehide", () => lock());
        if (!window.isSecureContext || !crypto.subtle) {
            $("status").textContent = "This page must be opened over HTTPS";
            $("status").classList.add("error");
            $("unlock-button").disabled = true;
        }
        maskPasswordField();
        $("password").focus();
    }

    function updatePasswordLabel() {
        $("password-label").textContent = selectedVault().passwordLabel;
    }

    // not while unlocking: the label must stay that of the vault being opened
    function setVaultChoiceEnabled(enabled) {
        for (const radio of document.querySelectorAll("input[name=vault]")) {
            radio.disabled = !enabled;
        }
    }

    // Browsers ignore autocomplete="off" when offering to save a password, so where it can be masked with CSS, the
    // master password goes into a text field that they don't recognize as a password. Not on touch devices: their
    // keyboards may learn what is typed into text fields, but not into password fields.
    function maskPasswordField() {
        if (CSS.supports("-webkit-text-security", "disc") && matchMedia("(pointer: fine)").matches) {
            $("password").type = "text";
            $("password").classList.add("masked");
        }
    }

    init();
})();
