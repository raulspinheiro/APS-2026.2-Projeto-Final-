import { getRequest } from "@tanstack/react-start/server";
import { gateIdentityEnabled } from "./gate-identity.server";
import { auth, authConfigured } from "./server";

/**
 * Resolução de sessão no servidor (somente servidor).
 *
 * Como este app roda o próprio Better Auth na mesma origem `/api/auth/*`, o
 * cookie de sessão é enviado em toda requisição a este app — server functions E
 * loaders de SSR inclusos. Então resolvemos o usuário direto dos cookies da
 * requisição via `auth.api.getSession` (sem JWT cunhado pelo cliente). Nunca
 * confie num id de usuário vindo do cliente — só no resultado desta verificação.
 */

/** Verdadeiro quando um banco de verdade está configurado no servidor. */
const databaseConfigured = Boolean(process.env.DATABASE_URL?.trim());

/** Reexporta para quem chama poder ramificar sem importar `server.ts`. */
export { authConfigured };

if (databaseConfigured && !authConfigured) {
  console.error(
    "[auth] DATABASE_URL is set but auth is disabled (VITE_AUTH_ENABLED=false) " +
      "— requireUserId() will reject every request (fail closed) rather than " +
      "share one dev user on a real database.",
  );
}

/** Id do usuário de fallback de dev, usado só quando a auth está desligada (VITE_AUTH_ENABLED=false). */
export const DEV_USER_ID = "dev-user";

/**
 * Lançado por `requireUserId` quando quem chama não tem sessão válida. Carrega
 * `status: 401`; a mensagem é um contrato estável — compare
 * `err.message === "Unauthorized"` no cliente para mandar o visitante ao login.
 */
export class UnauthorizedError extends Error {
  readonly status = 401;
  constructor() {
    super("Unauthorized");
    this.name = "UnauthorizedError";
  }
}

export type VerifiedUser = { id: string; email: string | null };

/**
 * Resolve o usuário autenticado da requisição atual, ou `null` quando a auth não
 * está configurada / ninguém está autenticado. Seguro chamar de server functions
 * e loaders de SSR.
 *
 * `bearerToken` é para o PREVIEW AO VIVO: o app roda num iframe particionado
 * cujos cookies não chegam ao servidor, então `authMiddleware` encaminha a
 * sessão como bearer token, que apresentamos como `Authorization: Bearer …` (o
 * plugin `bearer` resolve). Quando publicado nenhum token é passado e o cookie
 * é usado.
 */
export async function getSessionUser(
  bearerToken?: string,
): Promise<VerifiedUser | null> {
  if (!authConfigured && !gateIdentityEnabled()) return null;
  const request = getRequest();
  if (!request) return null;
  let headers = request.headers;
  if (bearerToken) {
    headers = new Headers(request.headers);
    headers.set("Authorization", `Bearer ${bearerToken}`);
  }
  const session = await auth.api.getSession({ headers });
  if (!session?.user) return null;
  return { id: session.user.id, email: session.user.email ?? null };
}

/**
 * Resolve o id do usuário atual para uma server function, ou lança quando não
 * autorizado. Prefira `authMiddleware` (`./middleware`), que chama isto por você.
 * - Auth ligada -> o id do usuário da sessão verificada; lança
 *   `UnauthorizedError` quando deslogado. Funciona no preview do sandbox também
 *   (login de verdade pelo cliente de preview embutido).
 * - Auth desligada (`VITE_AUTH_ENABLED=false`) + `DATABASE_URL` definido -> lança
 *   (falha fechada): um usuário de desenvolvimento compartilhado num banco de
 *   verdade deixaria todo visitante ler/escrever as linhas de todo mundo.
 * - Auth desligada + sem banco -> o id do usuário de desenvolvimento compartilhado.
 */
export async function requireUserId(bearerToken?: string): Promise<string> {
  if (!authConfigured && !gateIdentityEnabled()) {
    if (databaseConfigured) {
      throw new Error(
        "Auth is disabled (VITE_AUTH_ENABLED=false) but DATABASE_URL is set — " +
          "refusing to fall back to the shared dev user against a real database.",
      );
    }
    return DEV_USER_ID;
  }
  const user = await getSessionUser(bearerToken);
  if (!user) throw new UnauthorizedError();
  return user.id;
}
