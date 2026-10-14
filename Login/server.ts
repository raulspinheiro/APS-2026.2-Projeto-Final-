/**
 * Better Auth auto-hospedado DESTE app (somente servidor).
 *
 * Já preparado para preview ao vivo + deploy — não reescreva este arquivo. Para habilitar
 * e-mail/senha local, inverta só a flag em `./email-password` (veja a skill de auth).
 *
 * O app roda o próprio Better Auth em `/api/auth/*`, então o cookie de sessão fica
 * na própria origin deste app. O login federa no **broker de auth do Grok**
 * compartilhado (`GROK_AUTH_ISSUER`) via o plugin `genericOAuth` — o broker intermedia os
 * métodos de login upstream (Google, X, …) e guarda os segredos compartilhados; este
 * app só guarda o próprio client id/secret e indica o upstream desejado via
 * o hint `idp` de cada provedor.
 *
 * Três modos:
 *   - Implantado: o deployer injeta `GROK_AUTH_*` + `BETTER_AUTH_URL` por app
 *     + `DATABASE_URL`, então a auth federada de verdade persiste no Postgres.
 *   - Preview ao vivo do sandbox: sem injeção -> cai no **cliente de
 *     preview** compartilhado (`./preview`) e deriva a origin `https://*.grok-sandbox.com`
 *     do preview a partir da requisição, então o login real funciona (sem usuários de demo). Sessões
 *     e identidades persistem no banco PGLite embutido (o mesmo banco dos dados do app);
 *     reiniciar o processo apaga os dois. Clientes em iframe do preview ao vivo usam um bearer
 *     token (cookies particionados) — veja `client.ts`.
 *   - Desligado (`VITE_AUTH_ENABLED=false`, o padrão entregue): sem provedores;
 *     `requireUserId` resolve um usuário de dev sem banco configurado e
 *     lança de forma fechada quando `DATABASE_URL` está definido (veja `verify.server.ts`).
 *
 * NUNCA importe isto de código de cliente — puxa `pg` + o segredo de preview +
 * partes internas do Better Auth só de servidor. O cliente usa `@/lib/auth/client`;
 * componentes leem o usuário via `@/lib/auth/use-current-user`; server functions obtêm
 * um id verificado via `@/lib/auth/middleware`.
 */
import { betterAuth } from "better-auth";
import { bearer, genericOAuth } from "better-auth/plugins";
import { tanstackStartCookies } from "better-auth/tanstack-start";
import { getCookie } from "@tanstack/react-start/server";
import { randomBytes } from "node:crypto";
import { Pool } from "pg";
import { ensureDbReady, getPglite } from "../db";
import { emailAndPasswordEnabled } from "./email-password";
import { GATE_PROVIDER_ID, gateIdentitySessions } from "./gate-session.server";
import { GROK_PROVIDERS } from "./providers";
import { pgliteDialect } from "./pglite-dialect";
import {
  GROK_ISSUER_DEFAULT,
  PREVIEW_ALLOWED_HOSTS,
  PREVIEW_CLIENT_ID,
  PREVIEW_CLIENT_SECRET,
} from "./preview";

// Dispara (e compartilha) o bootstrap do PGLite assim que o módulo de auth do servidor carrega.
void ensureDbReady();

/**
 * O segredo de preview precisa sobreviver a recargas do módulo: o PGLite (e suas
 * linhas de sessão) fica em `globalThis`, então uma reavaliação por HMR deste
 * arquivo NÃO pode cunhar um novo segredo de assinatura, senão toda sessão
 * existente fica inválida no meio do dev. Reiniciar o processo limpa o segredo
 * e o PGLite juntos.
 */
const globalAuthRef = globalThis as typeof globalThis & {
  __grokAuthPreviewSecret__?: string;
};
function previewAuthSecret(): string {
  globalAuthRef.__grokAuthPreviewSecret__ ??= randomBytes(32).toString("hex");
  return globalAuthRef.__grokAuthPreviewSecret__;
}

/** Lê uma variável de ambiente, tratando vazio/espaço em branco como ausente. */
const env = (key: string): string | undefined => {
  const value = process.env[key]?.trim();
  return value ? value : undefined;
};

// Interruptor explícito de desligamento. O deployer define `VITE_AUTH_ENABLED=true` quando
// provisiona a auth; use "false" para forçar a auth desligada em todo lugar (usuário de dev).
const authDisabled = env("VITE_AUTH_ENABLED") === "false";

// Credenciais da federação do broker: o deployer injeta um cliente por app quando implantado;
// senão, cai no cliente compartilhado de preview ao vivo, que o broker aceita
// para qualquer callback `*.grok-sandbox.com` (veja `./preview`).
const grokIssuer = env("GROK_AUTH_ISSUER") ?? GROK_ISSUER_DEFAULT;
const grokClientId = env("GROK_AUTH_CLIENT_ID") ?? PREVIEW_CLIENT_ID;
const grokClientSecret = env("GROK_AUTH_CLIENT_SECRET") ?? PREVIEW_CLIENT_SECRET;

/** Verdadeiro quando o login federado está ativo (a auth de verdade é exigida). */
export const authConfigured =
  !authDisabled && Boolean(grokClientId && grokClientSecret);

// A própria origin do Better Auth deste app. Quando implantado, o deployer injeta a
// URL pública. No preview ao vivo do sandbox não há URL fixa (cada preview recebe
// um host dinâmico `*.grok-sandbox.com`), então passamos ao Better Auth um baseURL dinâmico:
// ele deriva a origin por requisição a partir do host (via proxy), validado contra a
// allowlist de preview, o que torna o `redirect_uri` do OAuth a URL concreta do preview
// que o cliente de preview do broker aceita.
const explicitBaseURL = env("BETTER_AUTH_URL");
// `string[]` explícito (não uma tupla readonly) — o DynamicBaseURLConfig do Better Auth
// exige um `allowedHosts: string[]` mutável.
const previewAllowedHosts: string[] = [...PREVIEW_ALLOWED_HOSTS];
// `npm run dev` local (contrato da porta 8080). O navegador pode enviar Origin como qualquer um
// destes para o mesmo servidor — confiar só em `localhost` rejeita `127.0.0.1` e
// quebra e-mail/senha com "Invalid origin".
const LOCAL_DEV_ORIGINS: string[] = [
  "http://localhost:8080",
  "http://127.0.0.1:8080",
  "http://[::1]:8080",
];
const baseURL = explicitBaseURL ?? {
  // Inclui hosts de loopback para o baseURL dinâmico resolver no e-mail/senha local
  // (não só o wildcard de preview).
  allowedHosts: [...previewAllowedHosts, "localhost", "127.0.0.1", "[::1]"],
  // `auto` → confia nas expansões http:// e https:// de allowedHosts
  // (preview é https; dev local é http).
  protocol: "auto" as const,
  fallback: "http://localhost:8080",
};

// Origins que o Better Auth aceita em POSTs autenticados (cadastro/login, etc.).
// Entradas faltando aqui aparecem como FORBIDDEN "Invalid origin".
const trustedOrigins: string[] = explicitBaseURL
  ? [explicitBaseURL, ...LOCAL_DEV_ORIGINS]
  : [
      // Wildcards de host (comparados com o host do Origin)
      ...previewAllowedHosts,
      // Wildcards de origin completa (comparados com o Origin)
      ...previewAllowedHosts.flatMap((host) => [`https://${host}`, `http://${host}`]),
      ...LOCAL_DEV_ORIGINS,
    ];

const databaseUrl = env("DATABASE_URL");

// Endpoints OAuth estáticos do broker (pula a discovery OIDC em cada login / callback).
// A discovery custaria um salto de rede extra até o broker antes do popup conseguir
// redirecionar para Google/X — o popup do preview ao vivo parecia travado no app durante
// toda essa ida e volta. Estes caminhos batem com o documento de discovery do broker.
const issuerBase = grokIssuer.replace(/\/+$/, "");
const grokAuthorizationUrl = `${issuerBase}/api/auth/oauth2/authorize`;
const grokTokenUrl = `${issuerBase}/api/auth/oauth2/token`;
const grokUserInfoUrl = `${issuerBase}/api/auth/oauth2/userinfo`;

// Postgres de verdade quando `DATABASE_URL` está definido (apps implantados); senão, o
// PGLite embutido do app (preview) via um dialeto Kysely — assim o Better Auth persiste no
// MESMO banco dos dados do app, inclusive usuários de e-mail/senha. Os dois usam o schema do
// Better Auth de `migrations/auth/0001_auth.sql`, copiado para `migrations/` quando
// o app liga o login.
const database = databaseUrl
  ? new Pool({ connectionString: databaseUrl })
  : { dialect: pgliteDialect(() => getPglite()), type: "postgres" as const };

/** Nome do cookie do token de sessão — também lido pela página de conclusão do popup do preview ao vivo. */
export const SESSION_TOKEN_COOKIE = "__Host-grok-auth.session_token";

// Montado à parte para a chamada `betterAuth({...})` continuar fácil de editar sem
// quebrar colchetes (modelos costumam tropeçar no spread condicional de plugin).
const grokOAuthPlugin = authConfigured
  ? genericOAuth({
      config: GROK_PROVIDERS.map(({ providerId, idp }) => ({
        providerId,
        clientId: grokClientId as string,
        clientSecret: grokClientSecret as string,
        // Prefere endpoints estáticos a `discoveryUrl` para iniciar (e
        // concluir) o OAuth sem esperar um fetch de discovery no broker.
        authorizationUrl: grokAuthorizationUrl,
        tokenUrl: grokTokenUrl,
        userInfoUrl: grokUserInfoUrl,
        scopes: ["openid", "profile", "email"],
        // `prompt: "login"` força o broker a reautenticar no
        // upstream em todo login, em vez de reusar em silêncio uma sessão
        // existente do broker. Junto com o broker enviar ao Google
        // `prompt=select_account`, o usuário sempre vê o seletor de conta
        // e pode escolher (ou trocar) com qual conta entrar.
        authorizationUrlParams: { idp, prompt: "login" },
      })),
    })
  : null;

export const auth = betterAuth({
  baseURL,
  // Apps implantados injetam BETTER_AUTH_SECRET. Preview: segredo estável no processo em
  // globalThis para o HMR não invalidar sessões no PGLite (veja acima).
  secret: env("BETTER_AUTH_SECRET") ?? previewAuthSecret(),
  database,

  // Checagem de CSRF / origin em POSTs de auth autenticados (cadastro/login por e-mail, …).
  // Veja a montagem de `trustedOrigins` acima — precisa cobrir hosts de preview ao vivo E
  // variantes de loopback local, senão os clientes recebem "Invalid origin".
  trustedOrigins,

  // Criptografa em repouso os tokens OAuth emitidos pelo broker e trata os upstreams
  // do broker como identidades confiáveis de primeira parte. O broker é dono da identidade e os e-mails do X são
  // sintéticos/não verificados, então SEM isto um login pode falhar com
  // `account_not_linked` (o Better Auth recusa anexar uma identidade não confiável e não
  // verificada a um usuário existente). Google e X trazem e-mails DISTINTOS, então isto
  // nunca os funde num único usuário — continuam identidades separadas.
  account: {
    encryptOAuthTokens: true,
    accountLinking: {
      enabled: true,
      trustedProviders: [
        ...GROK_PROVIDERS.map((p) => p.providerId),
        GATE_PROVIDER_ID,
      ],
      // O e-mail sintético do X nunca é "verified", então não condicione o vínculo ao
      // estado de e-mail verificado do usuário local.
      requireLocalEmailVerified: false,
    },
  },

  // Guarda a sessão no cookie assinado e curto `session_data` para as leituras
  // (inclusive o `/get-session` do cliente) pularem o banco — isso encolhe a janela de "loading"
  // e reduz o piscar da auth. Veja a skill `auth` para o guia completo
  // de evitar o piscar (condicione a `isPending`; faça SSR da sessão).
  session: { cookieCache: { enabled: true, maxAge: 300 } },

  // E-mail/senha local — ligado só via `./email-password` (não é um plugin).
  ...(emailAndPasswordEnabled ? { emailAndPassword: { enabled: true } } : {}),

  // Cookies com prefixo `__Host-`: o navegador RECUSA qualquer cookie de mesmo nome que
  // carregue um atributo `Domain`, então um app irmão `*.grok.me` não consegue "jogar" um
  // cookie de sessão `Domain=.grok.me` neste app. `__Host-` exige Secure +
  // Path=/ + sem Domain; o Better Auth usaria `__Secure-` (que permite
  // Domain), então tiramos o prefixo automático (`useSecureCookies: false`) e definimos
  // Secure + os nomes nós mesmos. (Navegadores permitem cookies Secure em
  // `http://localhost`, então o dev local continua funcionando.)
  advanced: {
    useSecureCookies: false,
    defaultCookieAttributes: { secure: true, sameSite: "lax", path: "/" },
    cookies: {
      session_token: { name: SESSION_TOKEN_COOKIE },
      session_data: { name: "__Host-grok-auth.session_data" },
      account_data: { name: "__Host-grok-auth.account_data" },
      dont_remember: { name: "__Host-grok-auth.dont_remember" },
    },
  },

  plugins: [
    gateIdentitySessions(),

    // Um provedor genericOAuth por upstream (quando a auth está ligada), todos federando
    // no broker com o MESMO cliente e diferindo só pelo hint `idp`.
    ...(grokOAuthPlugin ? [grokOAuthPlugin] : []),

    // Aceita `Authorization: Bearer <session-token>` como alternativa ao
    // cookie. Necessário no PREVIEW AO VIVO: o app roda num iframe embutido
    // onde os cookies são particionados, então depois do login no popup ele autentica com
    // um bearer token (veja `client.ts` / a skill `auth`). O hook só
    // dispara quando há um header Authorization, então o caminho do cookie
    // (apps implantados) não é afetado.
    bearer(),

    // Encaminha o Set-Cookie do Better Auth para as respostas do TanStack Start. PRECISA ser
    // o último para rodar depois dos hooks de todos os outros plugins.
    tanstackStartCookies(),
  ],
});

export function readSessionToken(): string | null {
  return getCookie(SESSION_TOKEN_COOKIE) ?? null;
}

// Reexportado por conveniência; o array vive no `providers.ts`, sem dependências,
// para o cliente também poder importá-lo.
export { GROK_PROVIDERS } from "./providers";
