import {
  BrowserRouter,
  Navigate,
  Route,
  Routes,
} from 'react-router-dom';

import {
  AuthProvider,
  useAuth,
} from './context/AuthContext';

import MainLayout from './components/layout/MainLayout';
import LoadingScreen from './components/ui/LoadingScreen';

import Admin from './pages/Admin';
import BreachCheck from './pages/BreachCheck';
import Community from './pages/Community';
import Dashboard from './pages/Dashboard';
import EmailAnalyzer from './pages/EmailAnalyzer';
import GoPhish from './pages/GoPhish';
import Landing from './pages/Landing';
import Login from './pages/Login';
import PenTest from './pages/PenTest';
import Recon from './pages/Recon';
import Register from './pages/Register';
import Resilience from './pages/Resilience';
import Settings from './pages/Settings';
import YaraScan from './pages/YaraScan';

function PublicRoute({ children }) {
  const { user, loading } = useAuth();

  if (loading) {
    return <LoadingScreen />;
  }

  if (user) {
    return <Navigate to="/dashboard" replace />;
  }

  return children;
}

function HomeRoute() {
  const { user, loading } = useAuth();

  if (loading) {
    return <LoadingScreen />;
  }

  if (user) {
    return <Navigate to="/dashboard" replace />;
  }

  return <Landing />;
}

function AppRoutes() {
  return (
    <Routes>
      <Route
        path="/"
        element={<HomeRoute />}
      />

      <Route
        path="/login"
        element={
          <PublicRoute>
            <Login />
          </PublicRoute>
        }
      />

      <Route
        path="/register"
        element={
          <PublicRoute>
            <Register />
          </PublicRoute>
        }
      />

      <Route element={<MainLayout />}>
        <Route
          path="/dashboard"
          element={<Dashboard />}
        />

        <Route
          path="/resilience"
          element={<Resilience />}
        />

        <Route
          path="/email-analyzer"
          element={<EmailAnalyzer />}
        />

        <Route
          path="/recon"
          element={<Recon />}
        />

        <Route
          path="/pentest"
          element={<PenTest />}
        />

        <Route
          path="/gophish"
          element={<GoPhish />}
        />

        <Route
          path="/yara"
          element={<YaraScan />}
        />

        <Route
          path="/breach"
          element={<BreachCheck />}
        />

        <Route
          path="/community"
          element={<Community />}
        />

        <Route
          path="/admin"
          element={<Admin />}
        />

        <Route
          path="/settings"
          element={<Settings />}
        />
      </Route>

      <Route
        path="*"
        element={<Navigate to="/" replace />}
      />
    </Routes>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </BrowserRouter>
  );
}