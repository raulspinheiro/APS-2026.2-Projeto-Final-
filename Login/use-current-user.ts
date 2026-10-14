import { useMemo } from "react";
import { authClient, authEnabled } from "./client";

/** Formato de usuário normalizado usado no app, com auth ligada ou desligada. */
export type AppUser = {
  id: string;
  displayName: string | null;
  primaryEmail: string | null;
  profileImageUrl: string | null;
  /** Verdadeiro quando este é o fallback de sandbox/dev (auth não configurada). */
  isDevFallback: boolean;
};

/**
 * Usuário de fallback estável, usado SÓ quando a auth está desligada
 * (`VITE_AUTH_ENABLED=false`, o padrão enviado). Com auth ligada, o preview ao
 * vivo do sandbox faz login de verdade pelo cliente de preview embutido. O id é
 * `"dev-user"` — o MESMO id que `verify.server.ts` devolve no servidor — então
 * linhas por usuário escritas nesse modo pertencem a um único dono consistente.
 */
export const DEV_USER: AppUser = {
  id: "dev-user",
  displayName: "Dev User",
  primaryEmail: "dev@example.com",
  profileImageUrl: null,
  isDevFallback: true,
};

/** Resultado de `useCurrentUserState()`: o usuário mais a flag de carregamento da sessão. */
export type CurrentUserState = {
  /** O usuário — `null` TANTO enquanto a sessão carrega QUANTO quando deslogado. */
  user: AppUser | null;
  /** Verdadeiro enquanto a sessão ainda está resolvendo — não trate `user: null` como deslogado ainda. */
  isPending: boolean;
};

const DEV_STATE: CurrentUserState = { user: DEV_USER, isPending: false };

/**
 * Usuário atual + estado de carregamento. O mesmo comportamento no preview ao
 * vivo e quando publicado:
 *   - Auth ligada -> o usuário autenticado de verdade; `user` é `null` enquanto
 *                            a sessão resolve (`isPending: true`) e quando
 *                            deslogado (`isPending: false`). A sessão vem do
 *                            `useSession()` do Better Auth → `/api/auth/get-session`
 *                            (cookie quando publicado; bearer no preview ao vivo).
 *   - Auth desligada (`VITE_AUTH_ENABLED=false`) -> `DEV_USER`, nunca pendente.
 *
 * Proteja uma rota esperando `isPending` acabar antes de agir sobre `user` —
 * redirecionar só com `user: null` manda visitantes autenticados para o login
 * em todo reload forçado:
 *
 *   import { RedirectToSignIn } from "@/lib/auth/gates";
 *   const { user, isPending } = useCurrentUserState();
 *   if (isPending) return null;              // ainda resolvendo — não redirecione ainda
 *   if (!user) return <RedirectToSignIn />;  // com certeza deslogado
 *
 * `authEnabled` é uma constante de módulo fixa no carregamento, então a chamada
 * de hook protegida mantém uma ordem de hooks estável em todo render de um
 * componente.
 */
export function useCurrentUserState(): CurrentUserState {
  if (!authEnabled) return DEV_STATE;
  // eslint-disable-next-line react-hooks/rules-of-hooks -- authEnabled é constante durante a vida do app
  return useSessionUserState();
}

function useSessionUserState(): CurrentUserState {
  const { data, isPending } = authClient.useSession();
  const id = data?.user.id;
  const displayName = data?.user.name ?? null;
  const primaryEmail = data?.user.email ?? null;
  const profileImageUrl = data?.user.image ?? null;
  const user = useMemo<AppUser | null>(
    () => (id ? { id, displayName, primaryEmail, profileImageUrl, isDevFallback: false } : null),
    [id, displayName, primaryEmail, profileImageUrl],
  );
  return useMemo(() => ({ user, isPending }), [user, isPending]);
}

/**
 * Visão de conveniência de `useCurrentUserState().user` para exibição (ex.:
 * `user?.displayName ?? "Guest"`). NOTA: `null` significa *carregando OU
 * deslogado* — para redirecionamentos e proteções de rota use `useCurrentUserState()` e
 * confira `isPending`.
 */
export function useCurrentUser(): AppUser | null {
  return useCurrentUserState().user;
}
