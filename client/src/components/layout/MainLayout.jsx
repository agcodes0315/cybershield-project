import { useState } from 'react';

import {
  Navigate,
  Outlet,
  useLocation,
} from 'react-router-dom';

import {
  AnimatePresence,
  motion,
} from 'framer-motion';

import { useAuth } from '../../context/AuthContext';
import LoadingScreen from '../ui/LoadingScreen';
import Header from './Header';
import Sidebar from './Sidebar';

export default function MainLayout() {
  const { user, loading } = useAuth();
  const location = useLocation();

  const [sidebarOpen, setSidebarOpen] =
    useState(false);

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

  return (
    <div className="app-shell">
      <Sidebar
        mobileOpen={sidebarOpen}
        onClose={() =>
          setSidebarOpen(false)
        }
      />

      <div className="app-workspace">
        <Header
          onMenuClick={() =>
            setSidebarOpen(true)
          }
        />

        <AnimatePresence mode="wait">
          <motion.main
            key={location.pathname}
            className="app-content"
            initial={{
              opacity: 0,
              y: 8,
            }}
            animate={{
              opacity: 1,
              y: 0,
            }}
            exit={{
              opacity: 0,
              y: -4,
            }}
            transition={{
              duration: 0.22,
              ease: 'easeOut',
            }}
          >
            <Outlet />
          </motion.main>
        </AnimatePresence>
      </div>
    </div>
  );
}