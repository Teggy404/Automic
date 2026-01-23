import { Navigate } from "react-router-dom";
import { useAuthStore } from "../../stores/authStore";

type ProtectedRouteProps = {
  children: React.ReactNode;
};

const AuthRoute = ({ children }: ProtectedRouteProps) => {
  const status = useAuthStore((s) => s.status);
  console.log(status);
  if (status === "loading") return <div>Loading...</div>;
  if (status === "unauthed") return <Navigate to="/" replace />;
  return <>{children}</>;
};

export default AuthRoute;
