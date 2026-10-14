import { createMiddleware } from "@tanstack/react-start";

/**
 * Middleware de auth para server functions — a forma padrão de obter o id do
 * usuário verificado de quem chama. Quando publicado, o cookie de sessão é
 * same-origin e vai junto automaticamente. No preview ao vivo o cliente também
 * encaminha o bearer token (cookies particionados) pelo hook `.client` abaixo —
 * os pontos de chamada não passam ele por conta própria.
 *
 *   import { createServerFn } from "@tanstack/react-start";
 *   import { getSql } from "@/lib/db";
 *   import { authMiddleware } from "@/lib/auth/middleware";
 *
 *   export const listTodos = createServerFn({ method: "GET" })
 *     .middleware([authMiddleware])
 *     .handler(async ({ context }) => {
 *       const sql = await getSql();
 *       return sql`select * from todos where user_id = ${context.userId}`;
 *     });
 *
 * Deslogado com auth ligada (preview ao vivo incluso) -> lança `UnauthorizedError`
 * (veja `verify.server.ts`). Com auth desligada (`VITE_AUTH_ENABLED=false`, o
 * padrão enviado) resolve o usuário de desenvolvimento compartilhado — mas lança
 * em vez disso quando um `DATABASE_URL` também está definido, então um app sem
 * login não deve usar isto. No caminho com auth ligada, use em toda server
 * function que toca dados por usuário e restrinja toda query por `context.userId`.
 */
export const authMiddleware = createMiddleware({ type: "function" })
  .client(async ({ next }) => {
    // Preview ao vivo (iframe particionado): a sessão vai num bearer token, não
    // num cookie, então encaminhe ao servidor. `null` quando publicado (auth por
    // cookie), então aqui não faz nada.
    const { getBearerToken } = await import("./client");
    return next({ sendContext: { bearerToken: getBearerToken() ?? undefined } });
  })
  .server(async ({ next, context }) => {
    // Importe SOMENTE módulos `*.server` aqui. Este arquivo é dual cliente/servidor
    // (hook de bearer no cliente). Um caminho simples `./isolation` foi renomeado
    // para `isolation.server.ts` — mantenha este import sincronizado para o `tsc`
    // da imagem resolver, e para o Vite não enviar `@tanstack/react-start/server`
    // ao navegador.
    const { assertSameSiteRequest } = await import("./isolation.server");
    const { requireUserId } = await import("./verify.server");
    // Rejeita requisições cross-site/irmãs com script antes de tocar dados por usuário.
    assertSameSiteRequest();
    const userId = await requireUserId(context.bearerToken);
    return next({ context: { userId } });
  });
