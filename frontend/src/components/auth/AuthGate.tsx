import { Navigate } from "react-router-dom";
import { useAuthStore } from "../../stores/authStore";

const AuthGate = () => {
  const status = useAuthStore((s) => s.status);

  if (status === "loading") return <div>Loading...</div>;
  if (status === "authed") return <Navigate to="/dashboard" replace />;
  return <div>Landing Page</div>;
};

export default AuthGate;
