import { Route, Routes } from "react-router-dom";
import AuthGate from "./components/auth/AuthGate";
import AuthRoute from "./components/auth/AuthRoute";
import MainLayout from "./components/MainLayout";

function App() {
  return (
      <Routes>
        <Route element={<MainLayout/>}>
          <Route path="/" element={<AuthGate />} />
          <Route
            path="/dashboard"
            element={
              <AuthRoute>
                <div>Dashboard</div>
              </AuthRoute>
            }
          />
        </Route>
      </Routes>
  );
}

export default App;
