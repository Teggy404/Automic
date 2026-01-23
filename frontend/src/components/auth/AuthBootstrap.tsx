import { useEffect } from "react";
import { useAuthStore } from "../../stores/authStore";
import type { AuthState } from "../../types/auth";

type AuthBootstrapProps = {
  children: React.ReactNode;
};

const AuthBootstrap = ({ children }: AuthBootstrapProps) => {
  const bootstrap = useAuthStore((s: AuthState) => s.bootstrap);

  useEffect(() => {
    bootstrap();
  }, [bootstrap]);
  return <>{children}</>;
};

export default AuthBootstrap;
