/**
 * Login local com e-mail/senha (banco Better Auth deste app — não o broker).
 *
 * Desligado por padrão. Para ativar: defina `emailAndPasswordEnabled` como
 * `true` abaixo e então monte os formulários de cadastro / login com
 * `authClient.signUp.email` / `authClient.signIn.email` de `@/lib/auth/client`
 * (veja a skill de auth).
 *
 * NÃO edite `server.ts` para isso — esse arquivo é configuração pré-ligada e congelada.
 */
export const emailAndPasswordEnabled = false;
