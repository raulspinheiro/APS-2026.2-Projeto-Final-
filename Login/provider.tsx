import type { ReactNode } from "react";

/**
 * Provider de cliente da aplicação inteira, montado uma vez perto da raiz (em
 * `src/routes/__root.tsx`):
 *
 *   <AuthProvider><Outlet /></AuthProvider>
 *
 * O cliente React do Better Auth (`@/lib/auth/client`) NÃO precisa de provider de
 * contexto — o `useSession()` funciona sozinho — então hoje isto só repassa os
 * filhos. Fica como o único ponto de montagem estável para futuros providers do
 * lado do cliente (ex.: um provider de toast ou de tema) sem mexer na casca da raiz.
 */
export function AuthProvider({ children }: { children: ReactNode }) {
  return <>{children}</>;
}
