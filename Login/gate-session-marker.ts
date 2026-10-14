/**
 * Marcador legível pelo cliente para sessões materializadas pelo gate ("Sign in
 * with Grok": sessões sem clique criadas por `gate-session.server.ts`). Sair de
 * uma sessão de gate não faz nada — a próxima requisição a rematerializa a
 * partir de `x-grok-identity` — então `UserButton` usa isto para esconder o
 * controle de logout. Prefixo `__Host-` como os outros cookies de auth: os
 * navegadores rejeitam um cookie `__Host-` que carregue `Domain`, então um app
 * irmão não confiável em `*.grok.me` não consegue plantar uma cópia no domínio
 * pai que a limpeza restrita ao host jamais expiraria.
 * Seguro no cliente: sem imports de servidor.
 */
export const GATE_SESSION_MARKER_COOKIE = "__Host-grok_gate_session";

export function hasGateSessionMarker(): boolean {
  if (typeof document === "undefined") return false;
  return document.cookie
    .split(";")
    .some((pair) => pair.trim().startsWith(`${GATE_SESSION_MARKER_COOKIE}=`));
}
