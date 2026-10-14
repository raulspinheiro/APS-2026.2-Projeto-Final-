import { getRequest } from "@tanstack/react-start/server";

/**
 * Isolamento de irmãos via Fetch-Metadata — **somente servidor** (sufixo `.server.ts`).
 *
 * PRECISA manter o sufixo `.server`: este arquivo importa
 * `@tanstack/react-start/server` (`getRequest` → `AsyncLocalStorage` do Node).
 * Se for importado de um módulo dual cliente/servidor com um nome que não seja
 * `.server`, o Vite manda ele para o navegador e o app morre com:
 * `AsyncLocalStorage is not a constructor`.
 *
 * Apps publicados em `*.grok.me` são "same-site" entre si, mas MUTUAMENTE NÃO
 * CONFIÁVEIS, e um cookie de sessão `SameSite=Lax` É enviado em subrequisições
 * same-site — então, sem isto, um irmão malicioso poderia fazer uma requisição
 * COM SCRIPT (fetch/XHR/form-POST) às server functions deste app e usar o cookie
 * de sessão deste app.
 *
 * Só permitimos: requisições same-origin (o próprio cliente deste app),
 * requisições que não vêm de navegador (SSR / servidor para servidor, que não
 * enviam `Sec-Fetch-Site`) e navegações GET de nível superior (como chegam o
 * callback OAuth e os carregamentos normais de página). Toda requisição
 * cross-site / same-site *com script* é rejeitada. Junto com cookies `__Host-`
 * e `trustedOrigins` do Better Auth, isto fecha a superfície de ataque entre
 * tenants irmãos. Aplicado no ponto de estrangulamento `authMiddleware`
 * (veja `middleware.ts`).
 */
export class CrossSiteRequestError extends Error {
  readonly status = 403;
  constructor() {
    super("Forbidden: cross-site request blocked");
    this.name = "CrossSiteRequestError";
  }
}

/** Lança `CrossSiteRequestError` para uma requisição cross-site/irmã com script. */
export function assertSameSiteRequest(): void {
  const request = getRequest();
  if (!request) return; // sem contexto de requisição (ex.: build) — nada a proteger
  const h = request.headers;
  const site = h.get("sec-fetch-site");
  // Cliente que não é navegador (sem header), a própria origem do app, ou um
  // carregamento direto (barra de endereço/favorito) estão todos ok.
  if (!site || site === "same-origin" || site === "none") return;
  // Uma navegação GET de nível superior (ex.: o redirect de callback OAuth do
  // broker) está ok mesmo sendo cross-site; requisições com script nunca definem
  // o modo navigate.
  const dest = h.get("sec-fetch-dest");
  const isTopLevelGet =
    h.get("sec-fetch-mode") === "navigate" &&
    request.method === "GET" &&
    dest !== "object" &&
    dest !== "embed";
  if (isTopLevelGet) return;
  throw new CrossSiteRequestError();
}
