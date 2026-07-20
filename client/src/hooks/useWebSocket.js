import {
  useCallback,
  useEffect,
  useRef,
  useState,
} from 'react';

const MAX_ALERTS = 50;
const RECONNECT_DELAY_MS = 3000;

function createEventKey(event) {
  return (
    event.event_id ||
    event.alert_id ||
    event.scan_id ||
    event.id ||
    [
      event.type,
      event.url,
      event.timestamp,
      event.created_at,
      event.message,
    ]
      .filter(Boolean)
      .join('|')
  );
}

export default function useWebSocket() {
  const socketRef = useRef(null);
  const reconnectTimerRef = useRef(null);
  const intentionallyClosedRef = useRef(false);
  const mountedRef = useRef(false);
  const seenEventKeysRef = useRef(new Set());

  const [connected, setConnected] = useState(false);
  const [alerts, setAlerts] = useState([]);
  const [lastEvent, setLastEvent] = useState(null);

  const clearReconnectTimer = useCallback(() => {
    if (reconnectTimerRef.current) {
      window.clearTimeout(reconnectTimerRef.current);
      reconnectTimerRef.current = null;
    }
  }, []);

  const addAlertOnce = useCallback((eventData) => {
    const eventKey = createEventKey(eventData);

    if (
      eventKey &&
      seenEventKeysRef.current.has(eventKey)
    ) {
      return;
    }

    if (eventKey) {
      seenEventKeysRef.current.add(eventKey);
    }

    setAlerts((previousAlerts) => {
      const nextAlerts = [
        eventData,
        ...previousAlerts,
      ].slice(0, MAX_ALERTS);

      const retainedKeys = new Set(
        nextAlerts
          .map(createEventKey)
          .filter(Boolean),
      );

      seenEventKeysRef.current = retainedKeys;

      return nextAlerts;
    });
  }, []);

  const connect = useCallback(() => {
    if (!mountedRef.current) {
      return;
    }

    const token = localStorage.getItem('token');

    if (!token) {
      setConnected(false);
      return;
    }

    const existingSocket = socketRef.current;

    if (
      existingSocket &&
      (
        existingSocket.readyState ===
          WebSocket.OPEN ||
        existingSocket.readyState ===
          WebSocket.CONNECTING
      )
    ) {
      return;
    }

    clearReconnectTimer();
    intentionallyClosedRef.current = false;

    const protocol =
      window.location.protocol === 'https:'
        ? 'wss'
        : 'ws';

    const hostname = window.location.hostname;

    const socketUrl =
      `${protocol}://${hostname}:5000/ws` +
      `?token=${encodeURIComponent(token)}`;

    const socket = new WebSocket(socketUrl);
    socketRef.current = socket;

    socket.onopen = () => {
      if (!mountedRef.current) {
        socket.close();
        return;
      }

      console.log('[WS] Connected');
      setConnected(true);
    };

    socket.onmessage = (messageEvent) => {
      if (!mountedRef.current) {
        return;
      }

      try {
        const eventData = JSON.parse(
          messageEvent.data,
        );

        setLastEvent(eventData);

        if (
          eventData.type === 'threat_alert' ||
          eventData.type === 'scan_complete'
        ) {
          addAlertOnce(eventData);
        }
      } catch (error) {
        console.warn(
          '[WS] Ignored invalid message:',
          error,
        );
      }
    };

    socket.onerror = () => {
      if (
        socket.readyState === WebSocket.OPEN ||
        socket.readyState ===
          WebSocket.CONNECTING
      ) {
        socket.close();
      }
    };

    socket.onclose = () => {
      if (socketRef.current === socket) {
        socketRef.current = null;
      }

      if (!mountedRef.current) {
        return;
      }

      setConnected(false);

      if (intentionallyClosedRef.current) {
        return;
      }

      console.log('[WS] Disconnected');

      clearReconnectTimer();

      reconnectTimerRef.current =
        window.setTimeout(() => {
          reconnectTimerRef.current = null;
          connect();
        }, RECONNECT_DELAY_MS);
    };
  }, [addAlertOnce, clearReconnectTimer]);

  useEffect(() => {
    mountedRef.current = true;
    intentionallyClosedRef.current = false;

    connect();

    return () => {
      mountedRef.current = false;
      intentionallyClosedRef.current = true;

      clearReconnectTimer();

      const socket = socketRef.current;
      socketRef.current = null;

      if (
        socket &&
        (
          socket.readyState === WebSocket.OPEN ||
          socket.readyState ===
            WebSocket.CONNECTING
        )
      ) {
        socket.close();
      }
    };
  }, [clearReconnectTimer, connect]);

  const clearAlerts = useCallback(() => {
    seenEventKeysRef.current.clear();
    setAlerts([]);
    setLastEvent(null);
  }, []);

  return {
    connected,
    alerts,
    lastEvent,
    clearAlerts,
  };
}