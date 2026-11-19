// The dashboard's one script: passkeys, showing a password, saving recovery codes, the
// resend countdown and sign-out. First-party, no libraries. Every form works without it
// except passkeys.
"use strict";

const fromB64url = (text) => {
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64 + "===".slice((b64.length + 3) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0)).buffer;
};

const toB64url = (buffer) => {
  let bin = "";
  for (const byte of new Uint8Array(buffer)) bin += String.fromCharCode(byte);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

const post = async (url, body) => {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body || {}),
    credentials: "same-origin",
  });
  // A fresh check is needed first: the server answered with 303, which fetch followed.
  if (response.redirected) {
    window.location.assign(response.url);
    throw new Error("redirected");
  }
  if (!response.ok) throw new Error(String(response.status));
  return response.json();
};

const credentialJson = (credential) => {
  const r = credential.response;
  const json = {
    id: credential.id,
    rawId: toB64url(credential.rawId),
    type: credential.type,
    clientExtensionResults: credential.getClientExtensionResults(),
    response: { clientDataJSON: toB64url(r.clientDataJSON) },
  };
  if (r.attestationObject) {
    json.response.attestationObject = toB64url(r.attestationObject);
    if (r.getTransports) json.response.transports = r.getTransports();
  } else {
    json.response.authenticatorData = toB64url(r.authenticatorData);
    json.response.signature = toB64url(r.signature);
    if (r.userHandle) json.response.userHandle = toB64url(r.userHandle);
  }
  if (credential.authenticatorAttachment) {
    json.authenticatorAttachment = credential.authenticatorAttachment;
  }
  return json;
};

// A passkey as the second step, or for a fresh check.
const usePasskey = async (button) => {
  const { challenge_id, options } = await post(button.dataset.options);
  options.challenge = fromB64url(options.challenge);
  (options.allowCredentials || []).forEach((c) => (c.id = fromB64url(c.id)));
  const credential = await navigator.credentials.get({ publicKey: options });
  return post(button.dataset.verify, {
    challenge_id,
    credential: credentialJson(credential),
    next: button.dataset.next || null,
  });
};

// Adding a passkey from Security.
const addPasskey = async () => {
  const { challenge_id, options } = await post("/admin/security/passkeys/options");
  options.challenge = fromB64url(options.challenge);
  options.user.id = fromB64url(options.user.id);
  (options.excludeCredentials || []).forEach((c) => (c.id = fromB64url(c.id)));
  const credential = await navigator.credentials.create({ publicKey: options });
  const label = (window.prompt("Name this passkey (for example, Pixel phone)") || "").trim();
  return post("/admin/security/passkeys/verify", {
    challenge_id,
    credential: credentialJson(credential),
    label: label || null,
  });
};

const say = (text) => {
  const error = document.getElementById("error");
  if (error) error.textContent = text;
};

document.querySelectorAll("button[data-action='passkey'], button[data-action='add-passkey']")
  .forEach((button) => {
    button.addEventListener("click", async () => {
      button.disabled = true;
      say("");
      try {
        const add = button.dataset.action === "add-passkey";
        const { next } = add ? await addPasskey() : await usePasskey(button);
        window.location.assign(next);
      } catch (e) {
        if (e.message === "redirected") return;
        say("That passkey didn’t work. Try again, or use another way.");
        button.disabled = false;
      }
    });
  });

// Show or hide a password.
document.querySelectorAll("button[data-show]").forEach((button) => {
  button.addEventListener("click", () => {
    const input = document.getElementById(button.dataset.show);
    const hidden = input.type === "password";
    input.type = hidden ? "text" : "password";
    button.textContent = hidden ? "Hide" : "Show";
  });
});

// Recovery codes: download as a text file, or copy.
const codesText = () => {
  const items = [...document.querySelectorAll("[data-codes] li")].map((li) => li.textContent);
  return `Pesa Clarity admin recovery codes (${location.host})\nEach works once.\n\n${items.join("\n")}\n`;
};

document.querySelectorAll("button[data-action='download-codes']").forEach((button) => {
  button.addEventListener("click", () => {
    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([codesText()], { type: "text/plain" }));
    link.download = "pesaclarity-admin-recovery-codes.txt";
    link.click();
    URL.revokeObjectURL(link.href);
  });
});

document.querySelectorAll("button[data-action='copy-codes']").forEach((button) => {
  button.addEventListener("click", async () => {
    await navigator.clipboard.writeText(codesText());
    button.textContent = "Copied";
  });
});

// "Open the dashboard" waits for the tick.
document.querySelectorAll("input[data-gate]").forEach((box) => {
  const target = document.getElementById(box.dataset.gate);
  const sync = () => target.classList.toggle("off", !box.checked);
  box.addEventListener("change", sync);
  sync();
});

// "Send a new code in 0:42".
document.querySelectorAll("button[data-wait]").forEach((button) => {
  let left = Number(button.dataset.wait);
  const tick = () => {
    left -= 1;
    if (left <= 0) {
      button.disabled = false;
      button.classList.remove("off");
      button.textContent = "Send a new code";
      return;
    }
    button.textContent = `Send a new code in ${Math.floor(left / 60)}:${String(left % 60).padStart(2, "0")}`;
    setTimeout(tick, 1000);
  };
  setTimeout(tick, 1000);
});

// Sign-out posts with fetch, so the request carries the page's Origin.
document.querySelectorAll("form[data-sign-out]").forEach((form) => {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    await fetch(form.action, { method: "POST", credentials: "same-origin" });
    window.location.assign("/admin/sign-in");
  });
});
