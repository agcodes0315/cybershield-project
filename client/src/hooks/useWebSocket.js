import {
  useCallback,
  useEffect,
  useRef,
  useState,
} from 'react';

const DEFAULT_PRODUCTION_WS_URL =
  'wss://cybershield-api-gateway.niceforest-87cbfff3.centralindia.azurecontainerapps.io/ws';

const MAX_ALERTS = 50;
const MAX_RECONNECT_DELAY = 30000;
const INITIAL_RECONNECT_DELAY = 3000;

function getStoredToken() {
  return (
    localStorage.getItem('cybershield_token') ||
    localStorage.getItem('token') ||
    localStorage.getItem('access_token') ||
    ''
  );
}

function getWebSocketBaseUrl() {
  const configuredUrl =
    import.meta.env.VITE_WS_URL?.trim();

  if (configuredUrl) {
    return configuredUrl.replace(/\/+$/, '');
  }

  if (
    window.location.hostname === 'localhost' ||
    window.location.hostname === '127.0.0.1'
  ) {
    return 'ws://127.0.0.1:5000/ws';
  }

  return DEFAULT_PRODUCTION_WS_URL;
}

function createSocketUrl(token) {
  const baseUrl = getWebSocketBaseUrl();
  const separator = baseUrl.includes('?') ? '&' : '?';

  return `${baseUrl}${separator}token=${encodeURIComponent(
    token,
  )}`;
}

function normalizeMessage(rawData) {
  if (typeof rawData !== 'string') {
    return rawData;
  }

  try {
    return JSON.parse(rawData);
  } catch {
    return {
      type: 'message',
      message: rawData,
      received_at: new Date().toISOString(),
    };
  }
}

function shouldAddToAlerts(event) {
  const eventType = String(
    event?.type || event?.event_type || '',
  ).toLowerCase();

  return [
    'threat_alert',
    'scan_complete',
    'incident_created',
    'incident_updated',
    'response_executed',
    'vulnerability_detected',
    'security_alert',
  ].includes(eventType);
}

export default function useWebSocket() {
  const socketRef = useRef(null);
  const reconnectTimerRef = useRef(null);
  const reconnectAttemptsRef = useRef(0);
  const mountedRef = useRef(false);
  const manualCloseRef = useRef(false);
  const connectingRef = useRef(false);

  const [connected, setConnected] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const [alerts, setAlerts] = useState([]);
  const [lastEvent, setLastEvent] = useState(null);
  const [error, setError] = useState('');
  const [lastConnectedAt, setLastConnectedAt] =
    useState(null);

  const clearReconnectTimer = useCallback(() => {
    if (reconnectTimerRef.current) {
      clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
  }, []);

  const closeSocket = useCallback(() => {
    clearReconnectTimer();

    const socket = socketRef.current;

    if (
      socket &&
      (socket.readyState === WebSocket.OPEN ||
        socket.readyState === WebSocket.CONNECTING)
    ) {
      manualCloseRef.current = true;
      socket.close(1000, 'Client cleanup');
    }

    socketRef.current = null;
    connectingRef.current = false;

    if (mountedRef.current) {
      setConnected(false);
      setConnecting(false);
    }
  }, [clearReconnectTimer]);

  const connect = useCallback(() => {
    if (!mountedRef.current) {
      return;
    }

    const token = getStoredToken();

    if (!token) {
      setConnected(false);
      setConnecting(false);
      setError(
        'WebSocket connection skipped because no authentication token was found.',
      );
      return;
    }

    const currentSocket = socketRef.current;

    if (
      currentSocket &&
      (currentSocket.readyState === WebSocket.OPEN ||
        currentSocket.readyState === WebSocket.CONNECTING)
    ) {
      return;
    }

    if (connectingRef.current) {
      return;
    }

    clearReconnectTimer();

    manualCloseRef.current = false;
    connectingRef.current = true;

    setConnecting(true);
    setError('');

    const socketUrl = createSocketUrl(token);

    console.log(
      '[WS] Connecting to:',
      socketUrl.split('?token=')[0],
    );

    let socket;

    try {
      socket = new WebSocket(socketUrl);
    } catch (connectionError) {
      connectingRef.current = false;
      setConnecting(false);
      setConnected(false);
      setError(
        connectionError?.message ||
          'Unable to create WebSocket connection.',
      );
      return;
    }

    socketRef.current = socket;

    socket.onopen = () => {
      if (!mountedRef.current) {
        socket.close();
        return;
      }

      reconnectAttemptsRef.current = 0;
      connectingRef.current = false;

      setConnected(true);
      setConnecting(false);
      setError('');
      setLastConnectedAt(new Date().toISOString());

      console.log('[WS] Connected');
    };

    socket.onmessage = (messageEvent) => {
      if (!mountedRef.current) {
        return;
      }

      const event = normalizeMessage(messageEvent.data);

      setLastEvent(event);

      if (shouldAddToAlerts(event)) {
        setAlerts((previousAlerts) => [
          event,
          ...previousAlerts,
        ].slice(0, MAX_ALERTS));
      }
    };

    socket.onerror = () => {
      if (!mountedRef.current) {
        return;
      }

      setError(
        'The real-time security feed could not establish a connection.',
      );

      console.error('[WS] Connection error');
    };

    socket.onclose = (closeEvent) => {
      socketRef.current = null;
      connectingRef.current = false;

      if (!mountedRef.current) {
        return;
      }

      setConnected(false);
      setConnecting(false);

      console.log(
        '[WS] Disconnected',
        closeEvent.code,
        closeEvent.reason || '',
      );

      if (manualCloseRef.current) {
        manualCloseRef.current = false;
        return;
      }

      const tokenStillExists = Boolean(getStoredToken());

      if (!tokenStillExists) {
        setError(
          'The real-time feed stopped because the authentication token is unavailable.',
        );
        return;
      }

      reconnectAttemptsRef.current += 1;

      const reconnectDelay = Math.min(
        INITIAL_RECONNECT_DELAY *
          2 **
            Math.min(
              reconnectAttemptsRef.current - 1,
              4,
            ),
        MAX_RECONNECT_DELAY,
      );

      setError(
        `Real-time feed disconnected. Reconnecting in ${Math.round(
          reconnectDelay / 1000,
        )} seconds.`,
      );

      reconnectTimerRef.current = setTimeout(() => {
        connect();
      }, reconnectDelay);
    };
  }, [clearReconnectTimer]);

  const reconnect = useCallback(() => {
    manualCloseRef.current = true;
    clearReconnectTimer();

    const socket = socketRef.current;

    if (socket) {
      socket.close();
      socketRef.current = null;
    }

    reconnectAttemptsRef.current = 0;
    connectingRef.current = false;

    setConnected(false);
    setConnecting(false);
    setError('');

    setTimeout(() => {
      if (mountedRef.current) {
        connect();
      }
    }, 250);
  }, [clearReconnectTimer, connect]);

  const sendMessage = useCallback((payload) => {
    const socket = socketRef.current;

    if (!socket || socket.readyState !== WebSocket.OPEN) {
      return false;
    }

    const message =
      typeof payload === 'string'
        ? payload
        : JSON.stringify(payload);

    socket.send(message);

    return true;
  }, []);

  const clearAlerts = useCallback(() => {
    setAlerts([]);
  }, []);

  useEffect(() => {
    mountedRef.current = true;

    connect();

    const handleStorageChange = (event) => {
      if (
        event.key === 'cybershield_token' ||
        event.key === 'token' ||
        event.key === 'access_token'
      ) {
        reconnect();
      }
    };

    window.addEventListener(
      'storage',
      handleStorageChange,
    );

    return () => {
      mountedRef.current = false;
      manualCloseRef.current = true;

      window.removeEventListener(
        'storage',
        handleStorageChange,
      );

      clearReconnectTimer();

      const socket = socketRef.current;

      if (
        socket &&
        (socket.readyState === WebSocket.OPEN ||
          socket.readyState === WebSocket.CONNECTING)
      ) {
        socket.close(1000, 'Component unmounted');
      }

      socketRef.current = null;
      connectingRef.current = false;
    };
  }, [clearReconnectTimer, connect, reconnect]);

  return {
    connected,
    connecting,
    alerts,
    lastEvent,
    error,
    lastConnectedAt,
    reconnect,
    clearAlerts,
    sendMessage,
  };
}