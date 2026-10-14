/**
 * Cliente OAuth compartilhado do PREVIEW AO VIVO (somente servidor — NUNCA
 * importe do cliente).
 *
 * O sandbox serve cada preview ao vivo numa URL dinâmica
 * `https://*.grok-sandbox.com`, que não dá para pré-registrar por app. O broker
 * em vez disso expõe UM cliente "preview" compartilhado que aceita qualquer
 * `https://*.grok-sandbox.com/api/auth/oauth2/callback/*`
 * (broker: `app-builder-deployer/auth/src/preview-oauth.ts`). Embutir aqui deixa
 * o preview ao vivo fazer login DE VERDADE — sem usuários de demonstração nem
 * simulados — sem injeção da plataforma. Quando publicado, o deployer injeta um `GROK_AUTH_*`
 * por app que sobrescreve estes (veja `server.ts`).
 *
 * Estes PRECISAM ser iguais a `GROK_PREVIEW_CLIENT_ID` /
 * `GROK_PREVIEW_CLIENT_SECRET` do broker (definidos no ambiente da Vercel do
 * broker; o broker guarda só o hash `base64url(SHA-256)` do segredo). Este é um
 * cliente dedicado e de baixo privilégio (só preview, `*.grok-sandbox.com`) —
 * rotacione regenerando a variável de ambiente do broker e esta constante juntas.
 */
export const PREVIEW_CLIENT_ID = "grok_preview";
export const PREVIEW_CLIENT_SECRET =
  "8bcdb7fc5a33874ad933ca568918d5790388a0795e44c4d1dea691f801b17ec5";

/** O emissor do broker de auth compartilhado (a descoberta OIDC fica embaixo dele). */
export const GROK_ISSUER_DEFAULT = "https://auth.grok.me";

/**
 * Padrões de host cujos callbacks o cliente de preview aceita. O Better Auth
 * deriva a origem real do preview ao vivo a partir do host da requisição e
 * valida contra esta lista (correspondência por curinga), então o `redirect_uri` do OAuth
 * vira o concreto `https://<preview-host>/api/auth/oauth2/callback/...` que o
 * broker permite.
 */
export const PREVIEW_ALLOWED_HOSTS = ["*.grok-sandbox.com"] as const;
