// The dashboard's one script: the passkey ceremonies and sign-out. First-party, no libraries.
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

const signIn = async () => {
  const { challenge_id, options } = await post("/admin/sign-in/options");
  options.challenge = fromB64url(options.challenge);
  (options.allowCredentials || []).forEach((c) => (c.id = fromB64url(c.id)));
  const credential = await navigator.credentials.get({ publicKey: options });
  return post("/admin/sign-in/verify", { challenge_id, credential: credentialJson(credential) });
};

const enrol = async (token) => {
  const { challenge_id, options } = await post("/admin/enrol/options", { token });
  options.challenge = fromB64url(options.challenge);
  options.user.id = fromB64url(options.user.id);
  (options.excludeCredentials || []).forEach((c) => (c.id = fromB64url(c.id)));
  const credential = await navigator.credentials.create({ publicKey: options });
  return post("/admin/enrol/verify", {
    token,
    challenge_id,
    credential: credentialJson(credential),
  });
};

const wire = (button) => {
  const error = document.getElementById("error");
  button.addEventListener("click", async () => {
    button.disabled = true;
    error.textContent = "";
    try {
      const { next } =
        button.dataset.action === "enrol" ? await enrol(button.dataset.token) : await signIn();
      window.location.assign(next);
    } catch (e) {
      error.textContent = "That did not work. Try again, or use another passkey.";
      button.disabled = false;
    }
  });
};

document.querySelectorAll("button[data-action]").forEach(wire);

// Sign-out posts with fetch, so the request carries the page's Origin.
document.querySelectorAll("form[data-sign-out]").forEach((form) => {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    await fetch(form.action, { method: "POST", credentials: "same-origin" });
    window.location.assign("/admin/sign-in");
  });
});
