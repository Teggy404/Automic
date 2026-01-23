import { Route, Routes } from "react-router-dom";
import AuthGate from "./components/auth/AuthGate";
import AuthRoute from "./components/auth/AuthRoute";

function App() {
  return (
    <Routes>
      <Route path="/" element={<AuthGate />} />
      <Route
        path="/dashboard"
        element={
          <AuthRoute>
            <div>Dashboard</div>
          </AuthRoute>
        }
      />
    </Routes>
  );
}

export default App;
