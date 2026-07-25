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
import MitreAttack from './pages/MitreAttack';
import PenTest from './pages/PenTest';
import Recon from './pages/Recon';
import Register from './pages/Register';
import Resilience from './pages/Resilience';
import ResponseOrchestrator from './pages/ResponseOrchestrator';
import Settings from './pages/Settings';
import ThreatIntelligence from './pages/ThreatIntelligence';
import YaraScan from './pages/YaraScan';

function PublicRoute({ children }) {
  const { user, loading } = useAuth();

  if (loading) {
    return <LoadingScreen />;
  }

  if (user) {
    return (
      <Navigate
        to="/dashboard"
        replace
      />
    );
  }

  return children;
}

function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();

  if (loading) {
    return <LoadingScreen />;
  }

  if (!user) {
    return (
      <Navigate
        to="/login"
        replace
      />
    );
  }

  return children;
}

function AdminRoute({ children }) {
  const { user, loading } = useAuth();

  if (loading) {
    return <LoadingScreen />;
  }

  if (!user) {
    return (
      <Navigate
        to="/login"
        replace
      />
    );
  }

  if (user.role !== 'admin') {
    return (
      <Navigate
        to="/dashboard"
        replace
      />
    );
  }

  return children;
}

function HomeRoute() {
  const { user, loading } = useAuth();

  if (loading) {
    return <LoadingScreen />;
  }

  if (user) {
    return (
      <Navigate
        to="/dashboard"
        replace
      />
    );
  }

  return <Landing />;
}

function ProtectedLayout() {
  return (
    <ProtectedRoute>
      <MainLayout />
    </ProtectedRoute>
  );
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

      <Route element={<ProtectedLayout />}>
        <Route
          path="/dashboard"
          element={<Dashboard />}
        />

        <Route
          path="/resilience"
          element={<Resilience />}
        />

        <Route
          path="/response-orchestrator"
          element={<ResponseOrchestrator />}
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
          path="/threat-intelligence"
          element={<ThreatIntelligence />}
        />

        <Route
          path="/mitre"
          element={<MitreAttack />}
        />

        <Route
          path="/breach"
          element={<BreachCheck />}
        />

        <Route
          path="/pentest"
          element={<PenTest />}
        />

        <Route
          path="/yara"
          element={<YaraScan />}
        />

        <Route
          path="/gophish"
          element={<GoPhish />}
        />

        <Route
          path="/community"
          element={<Community />}
        />

        <Route
          path="/settings"
          element={<Settings />}
        />

        <Route
          path="/admin"
          element={
            <AdminRoute>
              <Admin />
            </AdminRoute>
          }
        />
      </Route>

      <Route
        path="*"
        element={
          <Navigate
            to="/"
            replace
          />
        }
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