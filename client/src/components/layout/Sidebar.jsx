import { NavLink } from 'react-router-dom';
import {
  Activity,
  BarChart3,
  Bug,
  ChevronRight,
  CircleUserRound,
  FileSearch,
  Fingerprint,
  Globe2,
  LayoutDashboard,
  LifeBuoy,
  LockKeyhole,
  LogOut,
  MailSearch,
  Network,
  RadioTower,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Siren,
  TestTubeDiagonal,
  Users,
  X,
} from 'lucide-react';

import { useAuth } from '../../context/AuthContext';

const navigationGroups = [
  {
    title: 'Overview',
    items: [
      {
        to: '/dashboard',
        label: 'SOC Command Center',
        icon: LayoutDashboard,
      },
      {
        to: '/resilience',
        label: 'Cyber Resilience',
        icon: ShieldCheck,
      },
    ],
  },
  {
    title: 'Threat Intelligence',
    items: [
      {
        to: '/email-analyzer',
        label: 'Email Analyzer',
        icon: MailSearch,
      },
      {
        to: '/recon',
        label: 'Reconnaissance',
        icon: Globe2,
      },
      {
        to: '/breach',
        label: 'Breach Checker',
        icon: Fingerprint,
      },
    ],
  },
  {
    title: 'Security Operations',
    items: [
      {
        to: '/pentest',
        label: 'Pen Testing',
        icon: TestTubeDiagonal,
      },
      {
        to: '/yara',
        label: 'YARA Scanner',
        icon: FileSearch,
      },
      {
        to: '/gophish',
        label: 'GoPhish Simulator',
        icon: Bug,
      },
    ],
  },
  {
    title: 'Collaboration',
    items: [
      {
        to: '/community',
        label: 'SOC Community',
        icon: Users,
      },
      {
        to: '/settings',
        label: 'Settings',
        icon: Settings,
      },
    ],
  },
];

function SidebarLink({ item, onNavigate }) {
  const Icon = item.icon;

  return (
    <NavLink
      to={item.to}
      onClick={onNavigate}
      className={({ isActive }) =>
        `sidebar-link ${isActive ? 'sidebar-link-active' : ''}`
      }
    >
      <span className="sidebar-link-icon">
        <Icon size={17} strokeWidth={1.9} />
      </span>

      <span className="sidebar-link-label">{item.label}</span>

      <ChevronRight
        className="sidebar-link-arrow"
        size={15}
        strokeWidth={2}
      />
    </NavLink>
  );
}

export default function Sidebar({
  mobileOpen,
  onClose,
}) {
  const { user, logout } = useAuth();

  const handleLogout = () => {
    onClose();
    logout();
  };

  const userInitial =
    user?.username?.trim()?.charAt(0)?.toUpperCase() ||
    user?.email?.trim()?.charAt(0)?.toUpperCase() ||
    'U';

  return (
    <>
      <button
        type="button"
        className={`sidebar-overlay ${
          mobileOpen ? 'sidebar-overlay-visible' : ''
        }`}
        onClick={onClose}
        aria-label="Close navigation"
      />

      <aside
        className={`app-sidebar ${
          mobileOpen ? 'app-sidebar-open' : ''
        }`}
      >
        <div className="sidebar-brand">
          <div className="sidebar-brand-mark">
            <Shield size={23} strokeWidth={2.2} />
          </div>

          <div className="sidebar-brand-copy">
            <div className="sidebar-brand-name">
              CyberShield
            </div>

            <div className="sidebar-brand-subtitle">
              Security Operations
            </div>
          </div>

          <button
            type="button"
            className="sidebar-close-button"
            onClick={onClose}
            aria-label="Close sidebar"
          >
            <X size={20} />
          </button>
        </div>

        <div className="sidebar-status-card">
          <div className="sidebar-status-heading">
            <span className="sidebar-status-indicator" />

            <span>Platform operational</span>
          </div>

          <div className="sidebar-status-details">
            <span>Detection systems online</span>
            <strong>98%</strong>
          </div>

          <div className="sidebar-status-progress">
            <span />
          </div>
        </div>

        <nav className="sidebar-navigation">
          {navigationGroups.map((group) => (
            <section
              className="sidebar-group"
              key={group.title}
            >
              <div className="sidebar-group-title">
                {group.title}
              </div>

              <div className="sidebar-group-links">
                {group.items.map((item) => (
                  <SidebarLink
                    key={item.to}
                    item={item}
                    onNavigate={onClose}
                  />
                ))}
              </div>
            </section>
          ))}

          {user?.role === 'admin' && (
            <section className="sidebar-group">
              <div className="sidebar-group-title">
                Administration
              </div>

              <div className="sidebar-group-links">
                <SidebarLink
                  item={{
                    to: '/admin',
                    label: 'Admin Panel',
                    icon: LockKeyhole,
                  }}
                  onNavigate={onClose}
                />
              </div>
            </section>
          )}
        </nav>

        <div className="sidebar-footer">
          <div className="sidebar-user">
            <div className="sidebar-user-avatar">
              {userInitial}
            </div>

            <div className="sidebar-user-details">
              <div className="sidebar-user-name">
                {user?.username || 'CyberShield User'}
              </div>

              <div className="sidebar-user-role">
                <CircleUserRound size={12} />

                <span>
                  {user?.role === 'admin'
                    ? 'Administrator'
                    : 'SOC Analyst'}
                </span>
              </div>
            </div>
          </div>

          <button
            type="button"
            className="sidebar-logout-button"
            onClick={handleLogout}
          >
            <LogOut size={16} />

            <span>Sign out</span>
          </button>

          <div className="sidebar-version">
            CyberShield SOC · v2.1
          </div>
        </div>
      </aside>
    </>
  );
}