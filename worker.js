const DERIV_AUTH_URL = "https://auth.deriv.com/oauth2/auth";
const DERIV_TOKEN_URL = "https://auth.deriv.com/oauth2/token";
const DERIV_API_URL = "https://api.derivws.com";

const SESSION_COOKIE = "nl_session";
const OAUTH_TTL = 600;
const SESSION_TTL = 3600;

export default {
  async fetch(request, env) {
    try {
      const url = new URL(request.url);

      if (request.method === "OPTIONS") {
        return new Response(null, {
          headers: corsHeaders()
        });
      }

      // =========================
      // HOME
      // =========================
      if (url.pathname === "/") {
        return await homePage(request, env);
      }

      // =========================
      // LOGIN DERIV
      // =========================
      if (url.pathname === "/auth/deriv") {
        return await startDerivLogin(request, env);
      }

      // =========================
      // CALLBACK DERIV
      // =========================
      if (url.pathname === "/auth/callback") {
        return await derivCallback(request, env);
      }

      // =========================
      // API - CURRENT USER
      // =========================
      if (url.pathname === "/api/me") {
        return await apiMe(request, env);
      }

      // =========================
      // API - ACCOUNTS
      // =========================
      if (url.pathname === "/api/accounts") {
        return await apiAccounts(request, env);
      }

      // =========================
      // LOGOUT
      // =========================
      if (url.pathname === "/logout") {
        return await logout(request, env);
      }

      return new Response("Not Found", {
        status: 404,
        headers: {
          "content-type": "text/plain;charset=UTF-8"
        }
      });

    } catch (error) {
      console.error(error);

      return new Response(
        JSON.stringify({
          ok: false,
          error: "Internal server error"
        }),
        {
          status: 500,
          headers: {
            "content-type": "application/json;charset=UTF-8"
          }
        }
      );
    }
  }
};


// ============================================================
// HOME PAGE
// ============================================================

async function homePage(request, env) {
  const session = await getSession(request, env);

  if (!session) {
    return new Response(loginPage(), {
      headers: {
        "content-type": "text/html;charset=UTF-8"
      }
    });
  }

  return new Response(dashboardPage(session), {
    headers: {
      "content-type": "text/html;charset=UTF-8"
    }
  });
}


// ============================================================
// START DERIV OAUTH
// ============================================================

async function startDerivLogin(request, env) {

  if (!env.DERIV_CLIENT_ID) {
    return new Response(
      "DERIV_CLIENT_ID não configurado no Cloudflare Worker.",
      {
        status: 500,
        headers: {
          "content-type": "text/plain;charset=UTF-8"
        }
      }
    );
  }

  const redirectUri =
    env.DERIV_REDIRECT_URI ||
    new URL("/auth/callback", request.url).toString();

  // PKCE verifier
  const codeVerifier = randomString(64);

  // PKCE challenge
  const codeChallenge = await createCodeChallenge(codeVerifier);

  // CSRF state
  const state = randomString(32);

  // Guardamos verifier + state no KV.
  await env.NEVER_LOSS_KV.put(
    `oauth:${state}`,
    JSON.stringify({
      codeVerifier,
      createdAt: Date.now()
    }),
    {
      expirationTtl: OAUTH_TTL
    }
  );

  const params = new URLSearchParams();

  params.set("response_type", "code");
  params.set("client_id", env.DERIV_CLIENT_ID);
  params.set("redirect_uri", redirectUri);

  // Permissão necessária para consultar as contas.
  params.set("scope", "trade");

  params.set("state", state);
  params.set("code_challenge", codeChallenge);
  params.set("code_challenge_method", "S256");

  const loginUrl =
    `${DERIV_AUTH_URL}?${params.toString()}`;

  return Response.redirect(loginUrl, 302);
}


// ============================================================
// DERIV CALLBACK
// ============================================================

async function derivCallback(request, env) {

  const url = new URL(request.url);

  const error = url.searchParams.get("error");

  if (error) {
    return new Response(
      errorPage(
        "Login cancelado",
        "A autenticação na Deriv foi cancelada ou recusada."
      ),
      {
        status: 400,
        headers: {
          "content-type": "text/html;charset=UTF-8"
        }
      }
    );
  }

  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  if (!code || !state) {
    return new Response(
      errorPage(
        "Resposta inválida",
        "A Deriv não devolveu um código de autenticação válido."
      ),
      {
        status: 400,
        headers: {
          "content-type": "text/html;charset=UTF-8"
        }
      }
    );
  }

  // Recuperar PKCE
  const oauthData =
    await env.NEVER_LOSS_KV.get(`oauth:${state}`, "json");

  if (!oauthData) {
    return new Response(
      errorPage(
        "Sessão OAuth expirada",
        "Inicia novamente a conexão com a Deriv."
      ),
      {
        status: 400,
        headers: {
          "content-type": "text/html;charset=UTF-8"
        }
      }
    );
  }

  // Estado usado uma única vez.
  await env.NEVER_LOSS_KV.delete(`oauth:${state}`);

  const redirectUri =
    env.DERIV_REDIRECT_URI ||
    new URL("/auth/callback", request.url).toString();

  // Trocar authorization code por access token
  const tokenResponse = await fetch(
    DERIV_TOKEN_URL,
    {
      method: "POST",
      headers: {
        "content-type":
          "application/x-www-form-urlencoded"
      },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        client_id: env.DERIV_CLIENT_ID,
        code,
        code_verifier: oauthData.codeVerifier,
        redirect_uri: redirectUri
      })
    }
  );

  const tokenData = await tokenResponse.json();

  if (!tokenResponse.ok || !tokenData.access_token) {
    console.error("Deriv token error", tokenData);

    return new Response(
      errorPage(
        "Falha na conexão",
        "Não foi possível concluir a autenticação com a Deriv."
      ),
      {
        status: 500,
        headers: {
          "content-type": "text/html;charset=UTF-8"
        }
      }
    );
  }

  // Criar sessão interna
  const sessionId = randomString(48);

  const session = {
    accessToken: tokenData.access_token,
    tokenType: tokenData.token_type || "Bearer",
    expiresAt:
      Date.now() +
      ((tokenData.expires_in || 3600) * 1000),
    createdAt: Date.now()
  };

  await env.NEVER_LOSS_KV.put(
    `session:${sessionId}`,
    JSON.stringify(session),
    {
      expirationTtl: SESSION_TTL
    }
  );

  return new Response(
    dashboardPage(session),
    {
      status: 200,
      headers: {
        "content-type":
          "text/html;charset=UTF-8",
        "set-cookie":
          buildCookie(
            SESSION_COOKIE,
            sessionId,
            SESSION_TTL
          )
      }
    }
  );
}


// ============================================================
// API ME
// ============================================================

async function apiMe(request, env) {

  const session = await getSession(request, env);

  if (!session) {
    return json(
      {
        ok: false,
        authenticated: false
      },
      401
    );
  }

  return json({
    ok: true,
    authenticated: true,
    expiresAt: session.expiresAt
  });
}


// ============================================================
// API ACCOUNTS
// ============================================================

async function apiAccounts(request, env) {

  const session = await getSession(request, env);

  if (!session) {
    return json(
      {
        ok: false,
        error: "Not authenticated"
      },
      401
    );
  }

  if (
    session.expiresAt &&
    Date.now() > session.expiresAt
  ) {
    return json(
      {
        ok: false,
        error: "Session expired"
      },
      401
    );
  }

  const response = await fetch(
    `${DERIV_API_URL}/trading/v1/options/accounts`,
    {
      method: "GET",
      headers: {
        "Authorization":
          `Bearer ${session.accessToken}`
      }
    }
  );

  const data = await response.json();

  if (!response.ok) {
    console.error("Deriv accounts error", data);

    return json(
      {
        ok: false,
        error: "Não foi possível obter as contas Deriv.",
        deriv: data
      },
      response.status
    );
  }

  return json({
    ok: true,
    data
  });
}


// ============================================================
// LOGOUT
// ============================================================

async function logout(request, env) {

  const cookies =
    parseCookies(
      request.headers.get("Cookie") || ""
    );

  const sessionId =
    cookies[SESSION_COOKIE];

  if (sessionId) {
    await env.NEVER_LOSS_KV.delete(
      `session:${sessionId}`
    );
  }

  return new Response(
    loginPage(),
    {
      status: 200,
      headers: {
        "content-type":
          "text/html;charset=UTF-8",
        "set-cookie":
          `${SESSION_COOKIE}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`
      }
    }
  );
}


// ============================================================
// SESSION
// ============================================================

async function getSession(request, env) {

  const cookies =
    parseCookies(
      request.headers.get("Cookie") || ""
    );

  const sessionId =
    cookies[SESSION_COOKIE];

  if (!sessionId) {
    return null;
  }

  const session =
    await env.NEVER_LOSS_KV.get(
      `session:${sessionId}`,
      "json"
    );

  if (!session) {
    return null;
  }

  return session;
}


// ============================================================
// PKCE
// ============================================================

async function createCodeChallenge(verifier) {

  const data =
    new TextEncoder().encode(verifier);

  const digest =
    await crypto.subtle.digest(
      "SHA-256",
      data
    );

  return base64Url(
    new Uint8Array(digest)
  );
}


// ============================================================
// RANDOM
// ============================================================

function randomString(length) {

  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
    "abcdefghijklmnopqrstuvwxyz" +
    "0123456789-._~";

  const bytes =
    crypto.getRandomValues(
      new Uint8Array(length)
    );

  let result = "";

  for (const byte of bytes) {
    result +=
      chars[byte % chars.length];
  }

  return result;
}


// ============================================================
// BASE64 URL
// ============================================================

function base64Url(bytes) {

  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}


// ============================================================
// COOKIE
// ============================================================

function buildCookie(name, value, maxAge) {

  return [
    `${name}=${value}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
    `Max-Age=${maxAge}`
  ].join("; ");
}


// ============================================================
// COOKIE PARSER
// ============================================================

function parseCookies(header) {

  const cookies = {};

  for (const part of header.split(";")) {

    const index = part.indexOf("=");

    if (index === -1) continue;

    const key =
      part.substring(0, index).trim();

    const value =
      part.substring(index + 1).trim();

    cookies[key] = value;
  }

  return cookies;
}


// ============================================================
// JSON
// ============================================================

function json(data, status = 200) {

  return new Response(
    JSON.stringify(data, null, 2),
    {
      status,
      headers: {
        "content-type":
          "application/json;charset=UTF-8",
        ...corsHeaders()
      }
    }
  );
}


// ============================================================
// CORS
// ============================================================

function corsHeaders() {

  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers":
      "Content-Type, Authorization",
    "Access-Control-Allow-Methods":
      "GET, POST, OPTIONS"
  };
}


// ============================================================
// LOGIN PAGE
// ============================================================

function loginPage() {

  return `
<!DOCTYPE html>

<html lang="pt">
<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width, initial-scale=1.0">

<title>NEVER LOSS</title>

<style>

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  min-height: 100vh;
  background:
    radial-gradient(
      circle at top,
      #101b35 0%,
      #05070d 45%,
      #020307 100%
    );

  color: white;

  font-family:
    Arial,
    Helvetica,
    sans-serif;

  display: flex;
  align-items: center;
  justify-content: center;
}

.card {
  width: 92%;
  max-width: 430px;

  padding: 42px 28px;

  text-align: center;

  background:
    rgba(10,15,28,.92);

  border:
    1px solid rgba(255,255,255,.08);

  border-radius: 24px;

  box-shadow:
    0 25px 80px
    rgba(0,0,0,.55);
}

.logo {
  font-size: 38px;
  font-weight: 900;
  letter-spacing: 4px;
}

.version {
  margin-top: 8px;
  color: #64748b;
  font-size: 12px;
}

.subtitle {
  margin-top: 30px;

  color: #cbd5e1;

  font-size: 15px;

  line-height: 1.6;
}

.connect {
  display: block;

  width: 100%;

  margin-top: 32px;

  padding: 18px;

  border: none;

  border-radius: 14px;

  background:
    linear-gradient(
      135deg,
      #2563eb,
      #1d4ed8
    );

  color: white;

  font-size: 17px;

  font-weight: 800;

  text-decoration: none;

  cursor: pointer;

  box-shadow:
    0 10px 30px
    rgba(37,99,235,.25);
}

.connect:active {
  transform: scale(.98);
}

.info {
  margin-top: 25px;

  color: #64748b;

  font-size: 12px;

  line-height: 1.5;
}

</style>

</head>

<body>

<div class="card">

  <div class="logo">
    NEVER LOSS
  </div>

  <div class="version">
    DERIV ANALYTICS PLATFORM
  </div>

  <div class="subtitle">
    Conecte a sua conta Deriv para
    aceder aos dados da sua conta.
  </div>

  <a
    class="connect"
    href="/auth/deriv"
  >
    CONNECT TO DERIV
  </a>

  <div class="info">
    O login é realizado diretamente
    nos servidores oficiais da Deriv.
    <br><br>
    O NEVER LOSS não solicita a sua
    palavra-passe.
  </div>

</div>

</body>
</html>
`;
}


// ============================================================
// DASHBOARD
// ============================================================

function dashboardPage(session) {

  return `
<!DOCTYPE html>

<html lang="pt">

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width, initial-scale=1.0">

<title>NEVER LOSS</title>

<style>

* {
  box-sizing: border-box;
}

body {

  margin: 0;

  min-height: 100vh;

  background:
    #05070d;

  color: white;

  font-family:
    Arial,
    Helvetica,
    sans-serif;
}

.header {

  padding: 20px;

  border-bottom:
    1px solid
    rgba(255,255,255,.08);

  display: flex;

  justify-content: space-between;

  align-items: center;
}

.logo {

  font-size: 22px;

  font-weight: 900;

  letter-spacing: 2px;
}

.logout {

  color: #94a3b8;

  text-decoration: none;

  font-size: 13px;
}

.container {

  width: 92%;

  max-width: 900px;

  margin: auto;

  padding: 30px 0;
}

.status {

  padding: 18px;

  border-radius: 16px;

  background:
    rgba(16,185,129,.08);

  border:
    1px solid
    rgba(16,185,129,.2);

  color: #6ee7b7;

  margin-bottom: 25px;
}

.grid {

  display: grid;

  grid-template-columns:
    repeat(
      auto-fit,
      minmax(230px, 1fr)
    );

  gap: 18px;
}

.card {

  padding: 22px;

  background:
    #0b1120;

  border:
    1px solid
    rgba(255,255,255,.07);

  border-radius: 18px;
}

.title {

  color: #94a3b8;

  font-size: 12px;

  text-transform: uppercase;

  letter-spacing: 1px;

  margin-bottom: 10px;
}

.value {

  font-size: 25px;

  font-weight: 800;
}

.account {

  margin-top: 12px;

  padding: 14px;

  border-radius: 12px;

  background: #111827;
}

.account-type {

  font-size: 12px;

  color: #94a3b8;
}

.account-id {

  margin-top: 5px;

  font-size: 14px;

  color: #cbd5e1;
}

.balance {

  margin-top: 8px;

  font-size: 20px;

  font-weight: 700;
}

.loading {

  color: #94a3b8;

  text-align: center;

  padding: 30px;
}

.error {

  color: #fca5a5;

  background:
    rgba(239,68,68,.08);

  border:
    1px solid
    rgba(239,68,68,.2);

  padding: 15px;

  border-radius: 12px;
}

</style>

</head>

<body>

<header class="header">

  <div class="logo">
    NEVER LOSS
  </div>

  <a
    class="logout"
    href="/logout"
  >
    SAIR
  </a>

</header>

<main class="container">

  <div class="status">
    ✓ DERIV CONECTADA
  </div>

  <div class="grid">

    <div class="card">

      <div class="title">
        Estado
      </div>

      <div class="value">
        Conectado
      </div>

    </div>

    <div class="card">

      <div class="title">
        Contas Deriv
      </div>

      <div
        id="accounts"
        class="loading"
      >
        A carregar...
      </div>

    </div>

  </div>

</main>

<script>

async function loadAccounts() {

  const container =
    document.getElementById(
      "accounts"
    );

  try {

    const response =
      await fetch(
        "/api/accounts"
      );

    const result =
      await response.json();

    if (!response.ok ||
        !result.ok) {

      throw new Error(
        "Não foi possível carregar as contas."
      );
    }

    const data =
      result.data;

    const accounts =
      data.data || [];

    if (!accounts.length) {

      container.innerHTML =
        "<div>Não foram encontradas contas.</div>";

      return;
    }

    container.innerHTML =
      accounts.map(
        account => `

          <div class="account">

            <div class="account-type">

              ${escapeHtml(
                account.account_type ||
                "ACCOUNT"
              )}

            </div>

            <div class="account-id">

              ${escapeHtml(
                account.account_id ||
                ""
              )}

            </div>

            <div class="balance">

              ${escapeHtml(
                String(
                  account.balance ??
                  "-"
                )
              )}

              ${escapeHtml(
                account.currency ||
                ""
              )}

            </div>

          </div>

        `
      ).join("");

  } catch (error) {

    container.innerHTML = `
      <div class="error">
        ${escapeHtml(error.message)}
      </div>
    `;

  }
}

function escapeHtml(value) {

  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

loadAccounts();

</script>

</body>

</html>
`;
}


// ============================================================
// ERROR PAGE
// ============================================================

function errorPage(title, message) {

  return `
<!DOCTYPE html>

<html lang="pt">

<head>

<meta charset="UTF-8">

<meta name="viewport"
content="width=device-width, initial-scale=1.0">

<title>NEVER LOSS</title>

<style>

body {
  margin: 0;
  min-height: 100vh;
  background: #05
