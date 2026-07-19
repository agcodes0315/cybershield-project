import {
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';

import {
  useLocation,
  useNavigate,
} from 'react-router-dom';

import {
  Bell,
  Check,
  ChevronDown,
  CircleAlert,
  Command,
  LogOut,
  Menu,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  User,
  X,
} from 'lucide-react';

import { useAuth } from '../../context/AuthContext';

const routeMetadata = {
  '/dashboard': {
    eyebrow: 'Security Operations',
    title: 'SOC Command Center',
    description:
      'Monitor threats, incidents and platform health from one unified workspace.',
  },
  '/resilience': {
    eyebrow: 'Security Operations',
    title: 'Cyber Resilience',
    description:
      'Analyze attack paths, response readiness and organizational resilience.',
  },
  '/email-analyzer': {
    eyebrow: 'Threat Intelligence',
    title: 'Email Analyzer',
    description:
      'Inspect suspicious email headers, authentication records and phishing indicators.',
  },
  '/recon': {
    eyebrow: 'Threat Intelligence',
    title: 'Reconnaissance',
    description:
      'Gather authorized domain, DNS, network and infrastructure intelligence.',
  },
  '/pentest': {
    eyebrow: 'Security Operations',
    title: 'Pen Testing',
    description:
      'Run authorized security checks and review actionable findings.',
  },
  '/gophish': {
    eyebrow: 'Security Awareness',
    title: 'GoPhish Simulator',
    description:
      'Manage controlled phishing simulations and awareness exercises.',
  },
  '/yara': {
    eyebrow: 'Malware Analysis',
    title: 'YARA Scanner',
    description:
      'Inspect files, content and web resources using detection rules.',
  },
  '/breach': {
    eyebrow: 'Identity Intelligence',
    title: 'Breach Checker',
    description:
      'Identify exposed credentials and assess account breach risk safely.',
  },
  '/community': {
    eyebrow: 'Collaboration',
    title: 'SOC Community',
    description:
      'Collaborate with analysts and exchange defensive security knowledge.',
  },
  '/admin': {
    eyebrow: 'Administration',
    title: 'Admin Panel',
    description:
      'Manage platform access, configuration and operational controls.',
  },
  '/settings': {
    eyebrow: 'Workspace',
    title: 'Settings',
    description:
      'Configure your CyberShield workspace and user preferences.',
  },
};

const searchablePages = [
  {
    title: 'SOC Command Center',
    description: 'Dashboard, threats and platform health',
    path: '/dashboard',
  },
  {
    title: 'Cyber Resilience',
    description: 'Attack paths, response and resilience',
    path: '/resilience',
  },
  {
    title: 'Email Analyzer',
    description: 'Inspect suspicious email headers',
    path: '/email-analyzer',
  },
  {
    title: 'Reconnaissance',
    description: 'Domain and infrastructure intelligence',
    path: '/recon',
  },
  {
    title: 'Pen Testing',
    description: 'Authorized vulnerability testing',
    path: '/pentest',
  },
  {
    title: 'GoPhish Simulator',
    description: 'Controlled phishing simulations',
    path: '/gophish',
  },
  {
    title: 'YARA Scanner',
    description: 'Rule-based malware analysis',
    path: '/yara',
  },
  {
    title: 'Breach Checker',
    description: 'Credential exposure assessment',
    path: '/breach',
  },
  {
    title: 'SOC Community',
    description: 'Defensive security collaboration',
    path: '/community',
  },
  {
    title: 'Admin Panel',
    description: 'Users and operational controls',
    path: '/admin',
  },
  {
    title: 'Settings',
    description: 'Profile and workspace preferences',
    path: '/settings',
  },
];

const initialNotifications = [
  {
    id: 1,
    title: 'Elevated threat level',
    message:
      'CyberShield detected increased suspicious activity.',
    time: '2 minutes ago',
    unread: true,
  },
  {
    id: 2,
    title: 'YARA rules ready',
    message:
      'The malware detection rule library is available.',
    time: '18 minutes ago',
    unread: true,
  },
  {
    id: 3,
    title: 'Platform health check',
    message:
      'Detection engine and API gateway are operational.',
    time: '1 hour ago',
    unread: false,
  },
];

function formatDate() {
  return new Intl.DateTimeFormat('en-US', {
    weekday: 'short',
    day: '2-digit',
    month: 'short',
    year: 'numeric',
  }).format(new Date());
}

export default function Header({ onMenuClick }) {
  const location = useLocation();
  const navigate = useNavigate();

  const authContext = useAuth();
  const user = authContext?.user;
  const logout = authContext?.logout;

  const headerRef = useRef(null);
  const searchInputRef = useRef(null);

  const [searchQuery, setSearchQuery] =
    useState('');

  const [searchOpen, setSearchOpen] =
    useState(false);

  const [
    notificationsOpen,
    setNotificationsOpen,
  ] = useState(false);

  const [profileOpen, setProfileOpen] =
    useState(false);

  const [notifications, setNotifications] =
    useState(initialNotifications);

  const metadata = useMemo(
    () =>
      routeMetadata[location.pathname] || {
        eyebrow: 'CyberShield',
        title: 'Security Operations',
        description:
          'Monitor and manage your cybersecurity environment.',
      },
    [location.pathname],
  );

  const filteredPages = useMemo(() => {
    const normalizedQuery =
      searchQuery.trim().toLowerCase();

    if (!normalizedQuery) {
      return searchablePages;
    }

    return searchablePages.filter((page) => {
      const searchableText =
        `${page.title} ${page.description}`
          .toLowerCase();

      return searchableText.includes(
        normalizedQuery,
      );
    });
  }, [searchQuery]);

  const unreadCount = notifications.filter(
    (notification) => notification.unread,
  ).length;

  const username =
    user?.username ||
    user?.name ||
    'SOC Analyst';

  const userInitial =
    username.trim().charAt(0).toUpperCase() ||
    'U';

  const userRole =
    user?.role === 'admin'
      ? 'Administrator'
      : 'SOC Analyst';

  useEffect(() => {
    setSearchOpen(false);
    setNotificationsOpen(false);
    setProfileOpen(false);
    setSearchQuery('');
  }, [location.pathname]);

  useEffect(() => {
    const handleKeyboardShortcut = (event) => {
      const isSearchShortcut =
        (event.ctrlKey || event.metaKey) &&
        event.key.toLowerCase() === 'k';

      if (isSearchShortcut) {
        event.preventDefault();

        setSearchOpen(true);
        setNotificationsOpen(false);
        setProfileOpen(false);

        window.setTimeout(() => {
          searchInputRef.current?.focus();
        }, 0);
      }

      if (event.key === 'Escape') {
        setSearchOpen(false);
        setNotificationsOpen(false);
        setProfileOpen(false);
        searchInputRef.current?.blur();
      }
    };

    const handleOutsideClick = (event) => {
      if (
        headerRef.current &&
        !headerRef.current.contains(event.target)
      ) {
        setSearchOpen(false);
        setNotificationsOpen(false);
        setProfileOpen(false);
      }
    };

    document.addEventListener(
      'keydown',
      handleKeyboardShortcut,
    );

    document.addEventListener(
      'mousedown',
      handleOutsideClick,
    );

    return () => {
      document.removeEventListener(
        'keydown',
        handleKeyboardShortcut,
      );

      document.removeEventListener(
        'mousedown',
        handleOutsideClick,
      );
    };
  }, []);

  const openSearch = () => {
    setSearchOpen(true);
    setNotificationsOpen(false);
    setProfileOpen(false);
  };

  const toggleNotifications = () => {
    setNotificationsOpen((current) => !current);
    setProfileOpen(false);
    setSearchOpen(false);
  };

  const toggleProfile = () => {
    setProfileOpen((current) => !current);
    setNotificationsOpen(false);
    setSearchOpen(false);
  };

  const navigateToPage = (path) => {
    navigate(path);
    setSearchQuery('');
    setSearchOpen(false);
  };

  const handleSearchSubmit = (event) => {
    event.preventDefault();

    if (filteredPages.length > 0) {
      navigateToPage(filteredPages[0].path);
    }
  };

  const markNotificationRead = (id) => {
    setNotifications((current) =>
      current.map((notification) =>
        notification.id === id
          ? {
              ...notification,
              unread: false,
            }
          : notification,
      ),
    );
  };

  const markAllNotificationsRead = () => {
    setNotifications((current) =>
      current.map((notification) => ({
        ...notification,
        unread: false,
      })),
    );
  };

  const handleLogout = () => {
    setProfileOpen(false);

    if (typeof logout === 'function') {
      logout();
    } else {
      localStorage.removeItem('token');
      localStorage.removeItem('user');
    }

    navigate('/login', {
      replace: true,
    });
  };

  return (
    <>
      <style>
        {`
          .cyber-header-menu-wrapper {
            position: relative;
          }

          .cyber-header-dropdown {
            position: absolute;
            top: calc(100% + 12px);
            right: 0;
            z-index: 1000;
            width: 340px;
            overflow: hidden;
            border: 1px solid rgba(148, 163, 184, 0.18);
            border-radius: 16px;
            background: #0b1627;
            box-shadow:
              0 24px 70px rgba(0, 0, 0, 0.45),
              0 0 0 1px rgba(255, 255, 255, 0.02);
          }

          .cyber-search-results {
            right: auto;
            left: 0;
            width: 100%;
            min-width: 330px;
            max-height: 390px;
            overflow-y: auto;
          }

          .cyber-dropdown-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 12px;
            padding: 16px;
            border-bottom: 1px solid rgba(148, 163, 184, 0.12);
          }

          .cyber-dropdown-header strong {
            color: #f8fafc;
            font-size: 14px;
          }

          .cyber-dropdown-action {
            border: none;
            background: transparent;
            color: #60a5fa;
            font-size: 12px;
            cursor: pointer;
          }

          .cyber-dropdown-action:hover {
            color: #93c5fd;
          }

          .cyber-search-result,
          .cyber-notification-item,
          .cyber-profile-item {
            display: flex;
            width: 100%;
            align-items: flex-start;
            gap: 12px;
            border: none;
            background: transparent;
            padding: 13px 16px;
            color: #e2e8f0;
            text-align: left;
            cursor: pointer;
          }

          .cyber-search-result:hover,
          .cyber-notification-item:hover,
          .cyber-profile-item:hover {
            background: rgba(59, 130, 246, 0.1);
          }

          .cyber-search-icon,
          .cyber-notification-icon,
          .cyber-profile-icon {
            display: grid;
            width: 34px;
            height: 34px;
            flex: 0 0 34px;
            place-items: center;
            border-radius: 10px;
            background: rgba(59, 130, 246, 0.12);
            color: #60a5fa;
          }

          .cyber-result-copy,
          .cyber-notification-copy {
            min-width: 0;
            flex: 1;
          }

          .cyber-result-copy strong,
          .cyber-notification-copy strong {
            display: block;
            margin-bottom: 3px;
            color: #f8fafc;
            font-size: 13px;
          }

          .cyber-result-copy span,
          .cyber-notification-copy span {
            display: block;
            color: #94a3b8;
            font-size: 12px;
            line-height: 1.45;
          }

          .cyber-notification-copy small {
            display: block;
            margin-top: 6px;
            color: #64748b;
            font-size: 11px;
          }

          .cyber-notification-item {
            position: relative;
            border-bottom: 1px solid rgba(148, 163, 184, 0.08);
          }

          .cyber-notification-item:last-child {
            border-bottom: none;
          }

          .cyber-notification-unread {
            background: rgba(59, 130, 246, 0.055);
          }

          .cyber-unread-indicator {
            width: 7px;
            height: 7px;
            flex: 0 0 7px;
            margin-top: 8px;
            border-radius: 50%;
            background: #ef4444;
            box-shadow: 0 0 9px rgba(239, 68, 68, 0.75);
          }

          .cyber-notification-badge {
            position: absolute;
            top: -4px;
            right: -4px;
            display: grid;
            min-width: 17px;
            height: 17px;
            place-items: center;
            border: 2px solid #07111f;
            border-radius: 999px;
            background: #ef4444;
            color: white;
            font-size: 9px;
            font-weight: 700;
          }

          .cyber-profile-dropdown {
            width: 245px;
          }

          .cyber-profile-summary {
            padding: 16px;
            border-bottom: 1px solid rgba(148, 163, 184, 0.12);
          }

          .cyber-profile-summary strong {
            display: block;
            color: #f8fafc;
            font-size: 14px;
          }

          .cyber-profile-summary span {
            color: #94a3b8;
            font-size: 12px;
          }

          .cyber-profile-item {
            align-items: center;
            font-size: 13px;
          }

          .cyber-profile-logout {
            color: #fca5a5;
          }

          .cyber-profile-logout .cyber-profile-icon {
            background: rgba(239, 68, 68, 0.1);
            color: #f87171;
          }

          .cyber-empty-state {
            padding: 24px 16px;
            color: #94a3b8;
            text-align: center;
            font-size: 13px;
          }

          .cyber-search-container {
            position: relative;
          }

          .cyber-clear-search {
            display: grid;
            width: 25px;
            height: 25px;
            place-items: center;
            border: none;
            border-radius: 7px;
            background: transparent;
            color: #94a3b8;
            cursor: pointer;
          }

          .cyber-clear-search:hover {
            background: rgba(148, 163, 184, 0.12);
            color: #f8fafc;
          }

          .header-icon-button,
          .header-profile-button {
            position: relative;
          }

          @media (max-width: 760px) {
            .cyber-header-dropdown {
              position: fixed;
              top: 78px;
              right: 16px;
              left: 16px;
              width: auto;
              min-width: 0;
            }

            .cyber-search-results {
              top: 78px;
            }
          }
        `}
      </style>

      <header
        ref={headerRef}
        className="app-header"
      >
        <div className="header-main-row">
          <div className="header-title-area">
            <button
              type="button"
              className="mobile-menu-button"
              onClick={onMenuClick}
              aria-label="Open navigation"
            >
              <Menu size={21} />
            </button>

            <div>
              <div className="header-eyebrow">
                <span className="header-eyebrow-dot" />
                {metadata.eyebrow}
              </div>

              <h1 className="header-title">
                {metadata.title}
              </h1>

              <p className="header-description">
                {metadata.description}
              </p>
            </div>
          </div>

          <div className="header-actions">
            <div className="cyber-search-container">
              <form
                className={`header-search ${
                  searchOpen
                    ? 'header-search-open'
                    : ''
                }`}
                onSubmit={handleSearchSubmit}
              >
                <Search size={17} />

                <input
                  ref={searchInputRef}
                  type="search"
                  value={searchQuery}
                  placeholder="Search CyberShield"
                  aria-label="Search CyberShield"
                  autoComplete="off"
                  onFocus={openSearch}
                  onChange={(event) => {
                    setSearchQuery(
                      event.target.value,
                    );
                    openSearch();
                  }}
                />

                {searchQuery ? (
                  <button
                    type="button"
                    className="cyber-clear-search"
                    aria-label="Clear search"
                    onClick={() => {
                      setSearchQuery('');
                      searchInputRef.current?.focus();
                    }}
                  >
                    <X size={14} />
                  </button>
                ) : (
                  <span className="header-search-shortcut">
                    <Command size={12} /> K
                  </span>
                )}
              </form>

              {searchOpen && (
                <div
                  className="
                    cyber-header-dropdown
                    cyber-search-results
                  "
                >
                  <div className="cyber-dropdown-header">
                    <strong>
                      {searchQuery
                        ? 'Search results'
                        : 'CyberShield modules'}
                    </strong>

                    <span
                      style={{
                        color: '#64748b',
                        fontSize: '11px',
                      }}
                    >
                      Enter to open
                    </span>
                  </div>

                  {filteredPages.length > 0 ? (
                    filteredPages.map((page) => (
                      <button
                        key={page.path}
                        type="button"
                        className="cyber-search-result"
                        onClick={() =>
                          navigateToPage(page.path)
                        }
                      >
                        <span className="cyber-search-icon">
                          <Shield size={16} />
                        </span>

                        <span className="cyber-result-copy">
                          <strong>
                            {page.title}
                          </strong>

                          <span>
                            {page.description}
                          </span>
                        </span>
                      </button>
                    ))
                  ) : (
                    <div className="cyber-empty-state">
                      No CyberShield module matched
                      “{searchQuery}”.
                    </div>
                  )}
                </div>
              )}
            </div>

            <div className="cyber-header-menu-wrapper">
              <button
                type="button"
                className="header-icon-button"
                aria-label="View security alerts"
                aria-expanded={notificationsOpen}
                onClick={toggleNotifications}
              >
                <Bell size={19} />

                {unreadCount > 0 && (
                  <span className="cyber-notification-badge">
                    {unreadCount}
                  </span>
                )}
              </button>

              {notificationsOpen && (
                <div className="cyber-header-dropdown">
                  <div className="cyber-dropdown-header">
                    <strong>
                      Security notifications
                    </strong>

                    {unreadCount > 0 && (
                      <button
                        type="button"
                        className="cyber-dropdown-action"
                        onClick={
                          markAllNotificationsRead
                        }
                      >
                        Mark all read
                      </button>
                    )}
                  </div>

                  {notifications.map(
                    (notification) => (
                      <button
                        key={notification.id}
                        type="button"
                        className={`cyber-notification-item ${
                          notification.unread
                            ? 'cyber-notification-unread'
                            : ''
                        }`}
                        onClick={() =>
                          markNotificationRead(
                            notification.id,
                          )
                        }
                      >
                        <span className="cyber-notification-icon">
                          {notification.unread ? (
                            <CircleAlert size={16} />
                          ) : (
                            <Check size={16} />
                          )}
                        </span>

                        <span className="cyber-notification-copy">
                          <strong>
                            {notification.title}
                          </strong>

                          <span>
                            {notification.message}
                          </span>

                          <small>
                            {notification.time}
                          </small>
                        </span>

                        {notification.unread && (
                          <span className="cyber-unread-indicator" />
                        )}
                      </button>
                    ),
                  )}
                </div>
              )}
            </div>

            <div className="cyber-header-menu-wrapper">
              <button
                type="button"
                className="header-profile-button"
                aria-label="Open user menu"
                aria-expanded={profileOpen}
                onClick={toggleProfile}
              >
                <span className="header-profile-avatar">
                  {userInitial}
                </span>

                <span className="header-profile-copy">
                  <strong>{username}</strong>
                  <small>{userRole}</small>
                </span>

                <ChevronDown
                  size={15}
                  style={{
                    transform: profileOpen
                      ? 'rotate(180deg)'
                      : 'rotate(0deg)',
                    transition:
                      'transform 160ms ease',
                  }}
                />
              </button>

              {profileOpen && (
                <div
                  className="
                    cyber-header-dropdown
                    cyber-profile-dropdown
                  "
                >
                  <div className="cyber-profile-summary">
                    <strong>{username}</strong>
                    <span>{userRole}</span>
                  </div>

                  <button
                    type="button"
                    className="cyber-profile-item"
                    onClick={() =>
                      navigateToPage('/dashboard')
                    }
                  >
                    <span className="cyber-profile-icon">
                      <User size={16} />
                    </span>

                    My dashboard
                  </button>

                  <button
                    type="button"
                    className="cyber-profile-item"
                    onClick={() =>
                      navigateToPage('/settings')
                    }
                  >
                    <span className="cyber-profile-icon">
                      <Settings size={16} />
                    </span>

                    Account settings
                  </button>

                  <button
                    type="button"
                    className="
                      cyber-profile-item
                      cyber-profile-logout
                    "
                    onClick={handleLogout}
                  >
                    <span className="cyber-profile-icon">
                      <LogOut size={16} />
                    </span>

                    Sign out
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        <div className="header-context-row">
          <div className="header-context-item">
            <ShieldAlert size={15} />

            <span>Threat level</span>

            <strong className="header-threat-level">
              Elevated
            </strong>
          </div>

          <div className="header-divider" />

          <div className="header-context-item">
            <span>Workspace</span>
            <strong>Primary SOC</strong>
          </div>

          <div className="header-context-date">
            {formatDate()}
          </div>
        </div>
      </header>
    </>
  );
}