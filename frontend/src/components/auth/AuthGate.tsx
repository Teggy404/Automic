import { Navigate } from "react-router-dom";
import { useAuthStore } from "../../stores/authStore";
import LandingPage from "../../pages/LandingPage";

const AuthGate = () => {
  const status = useAuthStore((s) => s.status);

  if (status === "loading") return <div>Loading...</div>;
  if (status === "authed") return <Navigate to="/dashboard" replace />;
  return <LandingPage />;
};

export default AuthGate;
