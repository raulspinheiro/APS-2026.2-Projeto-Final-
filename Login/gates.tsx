import { useState, useSyncExternalStore, type ReactNode } from "react";
import { Navigate } from "@tanstack/react-router";
import { GROK_PROVIDERS, authEnabled, signIn, signOut } from "./client";
import { hasGateSessionMarker } from "./gate-session-marker";
import { resolveSignInGateState } from "./sign-in-gate";
import { useCurrentUser, useCurrentUserState } from "./use-current-user";

const subscribeToNothing = () => () => {};
const noGateSessionOnServer = () => false;

/**
 * Componentes de estado de auth — envoltórios simples em torno de `useCurrentUserState()`.
 *
 * Com auth ligada, os visitantes ficam deslogados até autenticar — no preview
 * ao vivo do sandbox também, que faz login de verdade. O usuário de
 * desenvolvimento compartilhado só aparece quando a auth está desligada
 * (`VITE_AUTH_ENABLED=false`, o padrão enviado). Enquanto a sessão ainda está
 * resolvendo, os gates que se importam com o estado deslogado não renderizam
 * nada, para não haver um lampejo de deslogado no reload forçado.
 */

/** Para onde `RedirectToSignIn` manda visitantes deslogados. Crie esta rota. */
export const SIGN_IN_PATH = "/login";

/** Renderiza os filhos só quando há um usuário (sessão real, ou o usuário de desenvolvimento com auth desligada). */
export function SignedIn({ children }: { children: ReactNode }) {
  const { user } = useCurrentUserState();
  return user ? <>{children}</> : null;
}

/**
 * Renderiza os filhos só quando SABEMOS que o visitante está deslogado
 * (`isPending` já limpou e não há usuário). Escondido enquanto a sessão ainda carrega.
 */
export function SignedOut({ children }: { children: ReactNode }) {
  const { user, isPending } = useCurrentUserState();
  if (isPending || user) return null;
  return <>{children}</>;
}

/**
 * Redirecionamento no cliente para a rota de login (`<Navigate>` do TanStack —
 * NÃO um reload completo de `window.location`). Uma navegação de página inteira
 * reinicia o SPA e roda de novo o carregamento da sessão, o que parece um segundo
 * "Loading…" em /login.
 *
 * Proteja rotas esperando `isPending` primeiro (veja `use-current-user`) e então
 * renderize isto.
 */
export function RedirectToSignIn({ to = SIGN_IN_PATH }: { to?: string }) {
  return <Navigate to={to} />;
}

export function SignInGate({
  children,
  fallback,
}: {
  children: ReactNode;
  fallback?: ReactNode;
}) {
  const { user, isPending } = useCurrentUserState();
  const state = resolveSignInGateState({ isPending, hasUser: user !== null });
  if (state === "pending") return null;
  if (state === "signed_in") return <>{children}</>;
  return <>{fallback ?? <SignInButtons />}</>;
}

export function SignInButtons() {
  return (
    <div className="flex w-full max-w-sm flex-col gap-2">
      {GROK_PROVIDERS.map((p) => (
        <button
          key={p.providerId}
          type="button"
          onClick={() => signIn(p.providerId, { callbackURL: "/" })}
          className="w-full cursor-pointer rounded-md border border-neutral-300 px-4 py-2 hover:bg-neutral-100 dark:border-neutral-700 dark:hover:bg-neutral-900"
        >
          Continue with {p.label}
        </button>
      ))}
    </div>
  );
}

/**
 * Etiqueta mínima de identidade autenticada + logout. Reestilize à vontade (veja a
 * skill `design-ui`). O logout só aparece quando a auth está ligada (o usuário
 * de desenvolvimento com auth desligada não tem do que sair) e a sessão não foi
 * materializada pelo gate — atrás do gate a próxima requisição autentica o
 * visitante de volta na hora, então um controle de logout ali é um loop quebrado.
 */
export function UserButton() {
  const user = useCurrentUser();
  // O logout pode levar um momento (e pode falhar quando publicado), então o
  // controle mostra que está trabalhando e não pode ser disparado duas vezes.
  const [signingOut, setSigningOut] = useState(false);
  const gateSession = useSyncExternalStore(
    subscribeToNothing,
    hasGateSessionMarker,
    noGateSessionOnServer,
  );
  if (!user) return null;
  const label = user.displayName ?? user.primaryEmail ?? "Account";
  return (
    <div className="flex items-center gap-2">
      {user.profileImageUrl ? (
        <img
          src={user.profileImageUrl}
          alt=""
          className="h-8 w-8 rounded-full object-cover"
        />
      ) : (
        <span className="grid h-8 w-8 place-items-center rounded-full bg-black/10 text-sm font-medium dark:bg-white/20">
          {label.charAt(0).toUpperCase()}
        </span>
      )}
      <span className="text-sm font-medium">{label}</span>
      {authEnabled && !gateSession && (
        <button
          type="button"
          disabled={signingOut}
          onClick={() => {
            setSigningOut(true);
            // Sucesso navega para fora; na falha, reabilita para poder tentar de novo.
            void signOut().catch(() => setSigningOut(false));
          }}
          className="cursor-pointer text-sm underline-offset-4 opacity-70 hover:underline disabled:cursor-wait disabled:no-underline"
        >
          {signingOut ? "Signing out…" : "Sign out"}
        </button>
      )}
    </div>
  );
}
