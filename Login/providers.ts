/**
 * Os provedores de identidade upstream que este app oferece no login (via o broker).
 *
 * Fonte da verdade para AMBOS o servidor (`server.ts`, um provedor `genericOAuth`
 * por entrada) e o cliente (`client.ts` / botões de login). Fica num módulo
 * próprio sem dependências para o cliente poder importar sem puxar a instância
 * Better Auth só de servidor (e `pg`) para o bundle do navegador.
 *
 * Cada app federa para o **broker de auth** compartilhado (`GROK_AUTH_ISSUER`),
 * que guarda os segredos reais de Google/X. O app nunca os vê — só conhece o
 * próprio client id/secret por app e qual upstream pedir ao broker (`idp`).
 *
 * Para adicionar um upstream (ex.: GitHub) quando o broker suportar: acrescente
 * uma entrada aqui (`{ providerId: "grok-github", idp: "github", label: "GitHub" }`).
 * O `providerId` é o id local deste app e o segmento do caminho de callback OAuth
 * (`/api/auth/oauth2/callback/<providerId>`); `idp` é a dica que o broker lê para
 * escolher o upstream (o id do Better Auth para o X ainda é `twitter`).
 */
export type GrokProvider = {
  /** Id local do provedor neste app; também o segmento do caminho de callback. */
  providerId: string;
  /** Dica de upstream para a qual o broker encaminha (id social do Better Auth). */
  idp: string;
  /** Rótulo legível do botão de login. */
  label: string;
};

export const GROK_PROVIDERS: readonly GrokProvider[] = [
  { providerId: "grok-google", idp: "google", label: "Google" },
  { providerId: "grok-x", idp: "twitter", label: "X" },
];
