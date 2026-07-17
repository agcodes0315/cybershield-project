import {
  BrowserRouter,
  Navigate,
  NavLink,
  Route,
  Routes,
} from 'react-router-dom';

import {
  AuthProvider,
  useAuth,
} from './context/AuthContext';

import Admin from './pages/Admin';
import BreachCheck from './pages/BreachCheck';
import Community from './pages/Community';
import Dashboard from './pages/Dashboard';
import EmailAnalyzer from './pages/EmailAnalyzer';
import GoPhish from './pages/GoPhish';
import Login from './pages/Login';
import PenTest from './pages/PenTest';
import Recon from './pages/Recon';
import Register from './pages/Register';
import Resilience from './pages/Resilience';
import Settings from './pages/Settings';
import YaraScan from './pages/YaraScan';

function Sidebar() {
  const { user, logout } = useAuth();

  const links = [
    {
      to: '/dashboard',
      label: 'Dashboard',
      icon: 'DB',
    },
    {
      to: '/resilience',
      label: 'Cyber Resilience',
      icon: 'CR',
    },
    {
      to: '/email-analyzer',
      label: 'Email Analyzer',
      icon: 'EA',
    },
    {
      to: '/recon',
      label: 'Reconnaissance',
      icon: 'RC',
    },
    {
      to: '/pentest',
      label: 'Pen Testing',
      icon: 'PT',
    },
    {
      to: '/gophish',
      label: 'GoPhish Simulator',
      icon: 'GP',
    },
    {
      to: '/yara',
      label: 'YARA Scanner',
      icon: 'YS',
    },
    {
      to: '/breach',
      label: 'Breach Checker',
      icon: 'BC',
    },
  ];

  if (user?.role === 'admin') {
    links.push({
      to: '/admin',
      label: 'Admin Panel',
      icon: 'AD',
    });
  }

  return (
    <aside
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        zIndex: 100,
        display: 'flex',
        width: '250px',
        height: '100vh',
        flexDirection: 'column',
        padding: '24px 16px',
        overflowY: 'auto',
        borderRight:
          '1px solid var(--border-subtle)',
        background: 'var(--bg-secondary)',
      }}
    >
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          marginBottom: '28px',
          padding: '0 8px',
        }}
      >
        <div
          style={{
            display: 'grid',
            width: 38,
            height: 38,
            placeItems: 'center',
            borderRadius: '11px',
            background:
              'linear-gradient(135deg, #38bdf8, #818cf8)',
            color: 'white',
            fontSize: '0.72rem',
            fontWeight: 900,
          }}
        >
          CS
        </div>

        <div>
          <div
            style={{
              color: 'var(--text-primary)',
              fontSize: '1.15rem',
              fontWeight: 800,
              letterSpacing: '-0.02em',
            }}
          >
            CyberShield
          </div>

          <div
            style={{
              marginTop: '1px',
              color: 'var(--text-muted)',
              fontSize: '0.62rem',
              fontWeight: 700,
              letterSpacing: '0.09em',
              textTransform: 'uppercase',
            }}
          >
            CNI Intelligence
          </div>
        </div>
      </div>

      <nav
        style={{
          display: 'flex',
          flex: 1,
          flexDirection: 'column',
          gap: '3px',
        }}
      >
        {links.map((link) => (
          <NavLink
            key={link.to}
            to={link.to}
            style={({ isActive }) => ({
              display: 'flex',
              alignItems: 'center',
              gap: '10px',
              padding: '10px 12px',
              border:
                isActive
                  ? '1px solid rgba(56,189,248,0.14)'
                  : '1px solid transparent',
              borderRadius: '10px',
              background: isActive
                ? 'rgba(56,189,248,0.09)'
                : 'transparent',
              color: isActive
                ? '#38bdf8'
                : 'var(--text-muted)',
              fontFamily: 'inherit',
              fontSize: '0.84rem',
              fontWeight: 650,
              textDecoration: 'none',
            })}
          >
            <span
              style={{
                display: 'grid',
                width: 26,
                height: 26,
                placeItems: 'center',
                borderRadius: '7px',
                background:
                  'rgba(255,255,255,0.035)',
                fontSize: '0.58rem',
                fontWeight: 900,
              }}
            >
              {link.icon}
            </span>

            {link.label}
          </NavLink>
        ))}
      </nav>

      <div
        style={{
          padding: '14px 12px',
          border:
            '1px solid var(--border-subtle)',
          borderRadius: '12px',
          background: 'var(--bg-card)',
        }}
      >
        <div
          style={{
            color: 'var(--text-primary)',
            fontSize: '0.82rem',
            fontWeight: 700,
          }}
        >
          {user?.username}
        </div>

        <div
          style={{
            marginTop: '2px',
            color: 'var(--text-muted)',
            fontSize: '0.7rem',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
          }}
        >
          {user?.email}
        </div>

        <button
          type="button"
          onClick={logout}
          style={{
            width: '100%',
            marginTop: '10px',
            padding: '8px',
            border:
              '1px solid rgba(248,113,113,0.18)',
            borderRadius: '8px',
            background:
              'rgba(248,113,113,0.08)',
            color: '#f87171',
            fontFamily: 'inherit',
            fontSize: '0.76rem',
            fontWeight: 700,
            cursor: 'pointer',
          }}
        >
          Logout
        </button>
      </div>
    </aside>
  );
}

function ProtectedLayout() {
  const { user, loading } = useAuth();

  if (loading) {
    return null;
  }

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  return (
    <div
      style={{
        display: 'flex',
        minHeight: '100vh',
      }}
    >
      <Sidebar />

      <main
        style={{
          flex: 1,
          minWidth: 0,
          minHeight: '100vh',
          marginLeft: '250px',
          padding: '32px 36px',
          background:
            'var(--gradient-bg), var(--bg-primary)',
        }}
      >
        <Routes>
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

          <Route
            path="*"
            element={
              <Navigate
                to="/dashboard"
                replace
              />
            }
          />
        </Routes>
      </main>
    </div>
  );
}

function AppRoutes() {
  const { user, loading } = useAuth();

  if (loading) {
    return null;
  }

  return (
    <Routes>
      <Route
        path="/login"
        element={
          user ? (
            <Navigate
              to="/dashboard"
              replace
            />
          ) : (
            <Login />
          )
        }
      />

      <Route
        path="/register"
        element={
          user ? (
            <Navigate
              to="/dashboard"
              replace
            />
          ) : (
            <Register />
          )
        }
      />

      <Route
        path="/*"
        element={<ProtectedLayout />}
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