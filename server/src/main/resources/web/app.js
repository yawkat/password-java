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

    async function fetchSalt() {
        const response = await request("salt");
        if (response.status === 404) {
            throw new Error("This server is not registered yet: there is no database to open");
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

    async function fetchDatabase(keys) {
        const empty = new Uint8Array(0);
        let clockOffset = 0;
        for (let attempt = 0; ; attempt++) {
            const header = await authHeader(keys, Date.now() + clockOffset, "GET", "/db", empty);
            const response = await request("db", {headers: {"X-Auth": header}});
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
                throw new Error("The server has no database yet");
            }
            if (!response.ok) {
                throw httpError("Could not fetch the database", response);
            }
            return new Uint8Array(await response.arrayBuffer());
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
            const json = JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode(plaintext.subarray(4, 4 + length)));
            // like the apps, accept missing fields and scalars other than strings
            return (json.data?.passwords ?? []).map(entry => ({
                name: String(entry?.name ?? ""),
                value: String(entry?.value ?? ""),
            }));
        } finally {
            plaintext.fill(0);
        }
    }

    async function unlock(password, onProgress) {
        onProgress("Fetching salt…");
        const installSalt = await fetchSalt();
        onProgress("Deriving keys, this can take a while on a slow device…");
        // let the message render: the key derivation blocks this thread
        await new Promise(resolve => requestAnimationFrame(() => setTimeout(resolve, 0)));
        const keys = await deriveKeys(password, installSalt);
        try {
            onProgress("Fetching database…");
            const blob = await fetchDatabase(keys);
            onProgress("Decrypting…");
            return await decrypt(keys, blob);
        } finally {
            wipeKeys(keys);
        }
    }

    // ---- UI ----

    const $ = id => document.getElementById(id);

    let entries = null;
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

    function filterEntries() {
        const query = $("search").value.trim().toLowerCase();
        for (const item of $("entry-list").children) {
            item.hidden = !item.dataset.name.includes(query);
        }
    }

    function showEntries(loaded) {
        entries = loaded;
        $("password").value = "";
        $("status").textContent = "";
        $("unlock").hidden = true;
        $("entries").hidden = false;
        $("search").value = "";
        $("entry-list").replaceChildren(...entries.map(renderEntry));
        $("search").focus();
        lastActivity = Date.now();
        lockTimer = setTimeout(checkIdle, LOCK_AFTER_MILLIS);
    }

    function lock(reason) {
        generation++;
        entries = null;
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
            button.disabled = true;
            $("status").classList.remove("error");
            try {
                const loaded = await unlock($("password").value, text => {
                    if (generation === started) {
                        $("status").textContent = text;
                    }
                });
                if (generation === started) {
                    showEntries(loaded);
                }
            } catch (e) {
                if (generation === started) {
                    $("status").textContent = e.message;
                    $("status").classList.add("error");
                }
            } finally {
                if (generation === started) {
                    button.disabled = false;
                }
            }
        }
        $("search").addEventListener("input", filterEntries);
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
