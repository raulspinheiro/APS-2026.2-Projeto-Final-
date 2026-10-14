/**
 * Popup de login do preview ao vivo — somente servidor (NUNCA importe do cliente).
 *
 * O preview do sandbox roda o app num iframe particionado, então o OAuth precisa
 * acontecer num popup de nível superior (cookies de primeira parte). Esta função é o
 * documento INTEIRO do popup — sem casca React:
 *
 *   Fase 1 (`?providerId=…`): inicia o OAuth no servidor e faz 302 direto para a
 *     página de login do broker / upstream. O popup nunca pinta o app.
 *   Fase 2 (`?done=1`): depois da ida e volta do broker, emite uma página HTML
 *     mínima que envia o token de sessão à janela que abriu e fecha. Sem
 *     hidratação do SPA, sem ida e volta de server function.
 *
 * Ligado automaticamente pelo plugin Vite `authPopupPlugin` em `vite.config.ts`
 * durante `npm run dev` (preview ao vivo). NÃO crie `src/routes/auth/popup.tsx` —
 * uma rota React aqui pinta a casca completa do app no popup. Quem abre fica em
 * `client.ts` (`signIn` → `openSignInPopup`).
 */
import { auth, SESSION_TOKEN_COOKIE } from "./server";

/** Formato da mensagem que o popup envia à janela que o abriu (precisa bater com `client.ts`). */
type PopupMessage = {
  source: "grok-auth-popup";
  token: string | null;
  error?: string;
};

/**
 * Trata `GET /auth/popup`. Invocado pelo plugin Vite `authPopupPlugin` (dev /
 * preview ao vivo). Não reexporte isto de um arquivo de rota React.
 */
export async function handleAuthPopupRequest(request: Request): Promise<Response> {
  const url = new URL(request.url);
  const done = url.searchParams.get("done") === "1";

  if (done) {
    const errored = url.searchParams.has("error");
    const token = errored ? null : readCookie(request, SESSION_TOKEN_COOKIE);
    const message: PopupMessage = {
      source: "grok-auth-popup",
      token,
      ...(errored ? { error: url.searchParams.get("error") ?? "sign_in_failed" } : {}),
    };
    return new Response(completionHtml(message), {
      status: 200,
      headers: {
        "content-type": "text/html; charset=utf-8",
        // Nunca faça cache de uma página que embute um token de sessão.
        "cache-control": "no-store",
      },
    });
  }

  const providerId = url.searchParams.get("providerId")?.trim();
  if (!providerId) {
    return new Response("Missing providerId", {
      status: 400,
      headers: { "content-type": "text/plain; charset=utf-8" },
    });
  }

  // Permaneça em primeira parte no callback para o cookie de sessão cair NESTE popup.
  const back = `${url.origin}/auth/popup?done=1`;
  try {
    const apiRes = await auth.api.signInWithOAuth2({
      body: {
        providerId,
        callbackURL: back,
        errorCallbackURL: `${back}&error=1`,
      },
      // Encaminha o host do preview para o Better Auth derivar o baseURL /
      // redirect_uri corretos para a origem dinâmica `*.grok-sandbox.com`.
      headers: request.headers,
      asResponse: true,
    });

    if (!apiRes.ok) {
      const detail = await apiRes.text().catch(() => "");
      return completionResponse({
        source: "grok-auth-popup",
        token: null,
        error: detail || `oauth_init_failed_${apiRes.status}`,
      });
    }

    const body = (await apiRes.json().catch(() => null)) as {
      url?: string;
    } | null;
    const location = body?.url;
    if (!location) {
      return completionResponse({
        source: "grok-auth-popup",
        token: null,
        error: "oauth_init_missing_url",
      });
    }

    // 302 para o broker (que encaminha sem UI para Google/X). Encaminhe qualquer
    // Set-Cookie (estado OAuth / PKCE) para o callback poder concluir neste popup.
    const headers = new Headers({ location, "cache-control": "no-store" });
    for (const cookie of apiRes.headers.getSetCookie()) {
      headers.append("set-cookie", cookie);
    }
    return new Response(null, { status: 302, headers });
  } catch (err) {
    const message = err instanceof Error ? err.message : "oauth_init_threw";
    return completionResponse({
      source: "grok-auth-popup",
      token: null,
      error: message,
    });
  }
}

function completionResponse(message: PopupMessage): Response {
  return new Response(completionHtml(message), {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "no-store",
    },
  });
}

/** HTML mínimo: faz postMessage do token para a janela que abriu e fecha. Sem React. */
function completionHtml(message: PopupMessage): string {
  // JSON é seguro dentro de um bloco <script type="application/json">; o script
  // inline só lê. Evita armadilhas de escape ao embutir no código-fonte JS.
  const payload = JSON.stringify(message).replace(/</g, "\\u003c");
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Signing in…</title>
<style>
  html,body{margin:0;min-height:100%;background:#0b0b0c;color:#a1a1aa;
    font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
  main{min-height:100vh;display:grid;place-items:center;padding:1.5rem;text-align:center}
</style>
</head>
<body>
<main><p>Signing you in…</p></main>
<script type="application/json" id="grok-auth-popup-msg">${payload}</script>
<script>
(function () {
  var el = document.getElementById("grok-auth-popup-msg");
  var msg = { source: "grok-auth-popup", token: null };
  try { if (el && el.textContent) msg = JSON.parse(el.textContent); } catch (e) {}
  try {
    if (window.opener) window.opener.postMessage(msg, window.location.origin);
  } catch (e) {}
  try { window.close(); } catch (e) {}
})();
</script>
</body>
</html>`;
}

/** Lê um único valor de cookie da requisição (lida com `=` dentro dos valores). */
function readCookie(request: Request, name: string): string | null {
  const header = request.headers.get("cookie");
  if (!header) return null;
  for (const part of header.split(";")) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const eq = trimmed.indexOf("=");
    if (eq <= 0) continue;
    if (trimmed.slice(0, eq) !== name) continue;
    const raw = trimmed.slice(eq + 1);
    try {
      return decodeURIComponent(raw);
    } catch {
      return raw;
    }
  }
  return null;
}
