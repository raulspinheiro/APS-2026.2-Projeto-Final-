import { genericOAuthClient } from "better-auth/client/plugins";
import { createAuthClient } from "better-auth/react";
import { runPreSignInSignOut, runSignOut } from "../../../scripts/sign-out-plan.mjs";
import { GROK_PROVIDERS } from "./providers";

/**
 * Cliente Better Auth para este SPA React (lado do navegador).
 *
 * Fala com o próprio Better Auth deste app na mesma origem `/api/auth/*`. No
 * preview ao vivo o app é um iframe embutido com cookies PARTICIONADOS, então
 * depois de um login por popup ele não consegue ler o cookie de sessão —
 * autentica com um bearer token (capturado do popup, veja `signIn`). O hook
 * `onRequest` anexa esse token quando presente; quando publicado (auth por
 * cookie) nenhum token fica armazenado, então nada muda.
 *
 * Para sair, chame `signOut()` abaixo, NÃO `authClient.signOut()`: a chamada
 * crua deixa o bearer token no lugar, e `onRequest` continua reanexando-o,
 * então o visitante permanece autenticado.
 */
export const authClient = createAuthClient({
  plugins: [genericOAuthClient()],
  fetchOptions: {
    onRequest(ctx) {
      const token = getBearerToken();
      if (token) ctx.headers.set("Authorization", `Bearer ${token}`);
      return ctx;
    },
  },
});

/**
 * Verdadeiro quando a UI de login deve aparecer — isto é, sempre que
 * `VITE_AUTH_ENABLED` não for `"false"`. O template enviado define como
 * `"false"` (`.grok/app-env.json`), o que seleciona o usuário de desenvolvimento
 * (veja `use-current-user`); com a chave removida, o login é real no preview
 * (cliente de preview embutido) e quando publicado (cliente injetado por app).
 */
export const authEnabled = import.meta.env.VITE_AUTH_ENABLED !== "false";

/** Os provedores upstream para os quais renderizar os botões de login. */
export { GROK_PROVIDERS };

// ── Bearer token do preview ao vivo ──────────────────────────────────────────
// O iframe de preview embutido tem cookies particionados, então guardamos o
// bearer token da sessão no sessionStorage e o anexamos a toda requisição
// Better Auth (e às server functions, via `@/lib/auth/middleware`). Vazio em
// todo lugar, exceto no preview depois de um login por popup, então o caminho
// por cookie fica intocado nos demais casos.
const BEARER_KEY = "grok-auth.bearer-token";

/** O bearer token de preview armazenado, ou null. */
export function getBearerToken(): string | null {
  if (typeof window === "undefined") return null;
  try {
    return window.sessionStorage.getItem(BEARER_KEY);
  } catch {
    return null;
  }
}

function setBearerToken(token: string | null): void {
  if (typeof window === "undefined") return;
  try {
    if (token) window.sessionStorage.setItem(BEARER_KEY, token);
    else window.sessionStorage.removeItem(BEARER_KEY);
  } catch {
    /* armazenamento indisponível — ignorar */
  }
}

/**
 * O preview ao vivo do sandbox roda este app dentro de um iframe em um host
 * `*.grok-sandbox.com`, onde um redirecionamento de página inteira para o
 * broker não funciona — então o login usa um popup ali e um redirecionamento
 * normal em todo o resto.
 */
function inLivePreview(): boolean {
  return (
    typeof window !== "undefined" &&
    window.location.hostname.endsWith(".grok-sandbox.com")
  );
}

/** Mensagem que o popup devolve à janela que o abriu quando o login termina. */
type PopupMessage = { source: "grok-auth-popup"; token: string | null; error?: string };

/**
 * Inicia o login com um provedor upstream (`providerId` de `GROK_PROVIDERS`),
 * federando pelo broker de auth do Grok.
 *
 * - **Preview ao vivo** (iframe `*.grok-sandbox.com`): abre um POPUP em
 *   `/auth/popup`, servido pelo plugin Vite do template (veja `vite.config.ts` +
 *   `popup.server.ts`) — 302 para o login do broker/upstream (sem a moldura do
 *   app) e, na volta, envia o bearer token da sessão. Guardamos e atualizamos a
 *   sessão; sem navegação de topo do iframe até o broker.
 * - **Publicado** (e local sem iframe): um redirecionamento normal de página
 *   inteira para o broker.
 *
 * De qualquer forma, limpa qualquer sessão local existente ANTES, para que
 * trocar de provedor realmente troque a identidade.
 */
export async function signIn(
  providerId: string,
  opts: { callbackURL?: string; errorCallbackURL?: string } = {},
): Promise<void> {
  const callbackURL = opts.callbackURL ?? "/";
  const errorCallbackURL = opts.errorCallbackURL ?? "/";

  // Abre o popup de forma SÍNCRONA no gesto do usuário — antes de qualquer await
  // (inclusive signOut). Esperar antes tira o privilégio de gesto do usuário em
  // alguns navegadores quando a janela de origem é um iframe de preview ao vivo
  // cross-origin.
  const popup = inLivePreview() ? openSignInPopup(providerId) : null;

  // Limpa qualquer sessão anterior para que trocar de provedor realmente troque
  // a identidade. Limitado porque o popup já está aberto — uma requisição que
  // nunca conclui o deixaria pendurado — mas limitado POR AMBIENTE: só o
  // servidor consegue encerrar uma sessão publicada, então cortar no 1,5s do
  // preview iniciaria o OAuth com a sessão antiga ainda ativa.
  await runPreSignInSignOut({
    livePreview: inLivePreview(),
    hasBearer: Boolean(getBearerToken()),
    requestSignOut: () => authClient.signOut(),
    clearToken: () => setBearerToken(null),
  });

  if (inLivePreview()) {
    if (!popup) throw new Error("Pop-up blocked — allow pop-ups for sign-in");
    const token = await waitForPopupToken(popup);
    if (!token) throw new Error("Sign-in was cancelled or failed");
    setBearerToken(token);
    // Atualiza o estado de sessão do cliente com o bearer anexado (onRequest).
    // Evita recarregar o iframe inteiro quando já estamos no destino — esse
    // reload era a sensação lenta de "ainda carregando depois que o popup fechou".
    try {
      await authClient.getSession();
    } catch {
      /* o estado de sessão se recupera no próximo fetch de useSession */
    }
    if (typeof window !== "undefined") {
      const dest = new URL(callbackURL, window.location.origin);
      const here = window.location;
      if (dest.origin !== here.origin || dest.pathname !== here.pathname || dest.search !== here.search) {
        window.location.href = callbackURL;
      }
    }
    return;
  }

  const { data, error } = await authClient.signIn.oauth2({
    providerId,
    callbackURL,
    errorCallbackURL,
  });
  if (error) throw new Error(error.message ?? "Sign-in failed");
  if (data?.url) window.location.href = data.url;
}

/**
 * Abre `/auth/popup` numa janela nova. Precisa rodar de forma síncrona dentro
 * do tratamento do clique (sem await antes disso). O caminho é servido pelo plugin
 * Vite do template (`authPopupPlugin` em vite.config.ts) — NÃO por uma rota React.
 *
 * Abre a URL real direto (não about:blank → assign). A partir de um iframe
 * cross-origin, a dança do about:blank costuma falhar no primeiro clique e a
 * janela acaba mostrando a casca do app.
 */
function openSignInPopup(providerId: string): Window | null {
  const origin = window.location.origin;
  const url = `${origin}/auth/popup?providerId=${encodeURIComponent(providerId)}`;
  // Nome único por tentativa para que uma tentativa anterior presa no SPA não seja reutilizada.
  const name = `grok-signin-${Date.now()}`;
  return window.open(url, name, "popup,width=500,height=650");
}

/**
 * Espera a página de conclusão do popup fazer postMessage do bearer da sessão
 * (ou o usuário dispensar o popup).
 */
function waitForPopupToken(popup: Window): Promise<string | null> {
  return new Promise((resolve) => {
    const origin = window.location.origin;
    let settled = false;
    let closeTimer: number | undefined;
    const settle = (token: string | null) => {
      if (settled) return;
      settled = true;
      cleanup();
      resolve(token);
    };
    const onMessage = (event: MessageEvent) => {
      if (event.origin !== origin) return;
      const data = event.data as PopupMessage | undefined;
      if (!data || data.source !== "grok-auth-popup") return;
      settle(data.token ?? null);
    };
    // Alternativa quando o usuário dispensa o popup. O período de graça deixa o
    // postMessage da página de conclusão vencer uma corrida com `popup.closed`.
    const pollTimer = window.setInterval(() => {
      if (!popup.closed) return;
      window.clearInterval(pollTimer);
      closeTimer = window.setTimeout(() => settle(null), 400);
    }, 300);
    function cleanup() {
      window.clearInterval(pollTimer);
      if (closeTimer !== undefined) window.clearTimeout(closeTimer);
      window.removeEventListener("message", onMessage);
    }
    window.addEventListener("message", onMessage);
  });
}

/**
 * Sai da sessão local DESTE app, limpa o token de preview e então redireciona.
 *
 * Use isto, nunca `authClient.signOut()` — veja a nota em `authClient`.
 * A sequência fica em `scripts/sign-out-plan.mjs` para poder ser testada.
 *
 * **Rejeita quando publicado se o servidor nunca confirmar.** Ali a sessão é
 * um cookie HttpOnly que só o servidor consegue limpar, então redirecionar
 * mesmo assim reportaria um logout que não aconteceu. `<UserButton />` cuida
 * disso; um controle feito à mão precisa capturar o erro e deixar o visitante
 * tentar de novo. No preview ao vivo a limpeza local basta, então sempre resolve.
 */
export async function signOut(redirectTo = "/"): Promise<void> {
  await runSignOut({
    livePreview: inLivePreview(),
    hasBearer: Boolean(getBearerToken()),
    // Better Auth resolve com `{ error }` em vez de rejeitar, então exponha uma
    // resposta falha como rejeição para a sequência agir.
    requestSignOut: async () => {
      const { error } = await authClient.signOut();
      if (error) throw new Error(error.message ?? "Sign-out failed");
    },
    clearToken: () => setBearerToken(null),
    redirect: () => {
      window.location.href = redirectTo;
    },
  });
}
