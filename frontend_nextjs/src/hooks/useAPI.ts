// Custom hooks for API interactions

import { useState, useEffect, useCallback } from 'react';
import { api, handleAPIError } from '@/lib/api';
import {
  SystemStatus,
  SolveRequest,
  SolveResponse,
  StatisticsResponse,
  HistoryResponse,
  APIError
} from '@/types/api';

// Generic API hook
export function useAPI<T>(
  apiCall: () => Promise<T>,
  dependencies: any[] = []
) {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const result = await apiCall();
      setData(result);
    } catch (err) {
      setError(handleAPIError(err as APIError));
    } finally {
      setLoading(false);
    }
  }, dependencies);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  return { data, loading, error, refetch: fetchData };
}

// System status hook
export function useSystemStatus() {
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchStatus = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const result = await api.getSystemStatus();
      setStatus(result);
    } catch (err) {
      setError(handleAPIError(err as APIError));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchStatus();
    
    // Auto-refresh every 30 seconds
    const interval = setInterval(fetchStatus, 30000);
    return () => clearInterval(interval);
  }, [fetchStatus]);

  return { status, loading, error, refetch: fetchStatus };
}

// Challenge solver hook
export function useChallengeSolver() {
  const [solving, setSolving] = useState(false);
  const [result, setResult] = useState<SolveResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const solveChallenge = useCallback(async (request: SolveRequest) => {
    try {
      setSolving(true);
      setError(null);
      setResult(null);
      
      const response = await api.solveChallenge(request);
      setResult(response);
      
      return response;
    } catch (err) {
      const errorMessage = handleAPIError(err as APIError);
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setSolving(false);
    }
  }, []);

  const reset = useCallback(() => {
    setResult(null);
    setError(null);
    setSolving(false);
  }, []);

  return {
    solving,
    result,
    error,
    solveChallenge,
    reset
  };
}

// Statistics hook
export function useStatistics() {
  return useAPI(() => api.getStatistics());
}

// History hook
export function useHistory(limit: number = 20) {
  return useAPI(() => api.getHistory(limit), [limit]);
}

// Real-time updates hook
export function useRealTimeUpdates() {
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());
  const [isConnected, setIsConnected] = useState(true);

  const triggerUpdate = useCallback(() => {
    setLastUpdate(new Date());
  }, []);

  // Simulate real-time updates (in a real app, this would use WebSockets)
  useEffect(() => {
    const interval = setInterval(() => {
      // Check if backend is still accessible
      api.healthCheck()
        .then(() => {
          setIsConnected(true);
          triggerUpdate();
        })
        .catch(() => {
          setIsConnected(false);
        });
    }, 10000); // Check every 10 seconds

    return () => clearInterval(interval);
  }, [triggerUpdate]);

  return {
    lastUpdate,
    isConnected,
    triggerUpdate
  };
}

// Local storage hook
export function useLocalStorage<T>(key: string, initialValue: T) {
  const [storedValue, setStoredValue] = useState<T>(() => {
    if (typeof window === 'undefined') {
      return initialValue;
    }
    
    try {
      const item = window.localStorage.getItem(key);
      return item ? JSON.parse(item) : initialValue;
    } catch (error) {
      console.warn(`Error reading localStorage key "${key}":`, error);
      return initialValue;
    }
  });

  const setValue = useCallback((value: T | ((val: T) => T)) => {
    try {
      const valueToStore = value instanceof Function ? value(storedValue) : value;
      setStoredValue(valueToStore);
      
      if (typeof window !== 'undefined') {
        window.localStorage.setItem(key, JSON.stringify(valueToStore));
      }
    } catch (error) {
      console.warn(`Error setting localStorage key "${key}":`, error);
    }
  }, [key, storedValue]);

  return [storedValue, setValue] as const;
}

// Debounced value hook
export function useDebounce<T>(value: T, delay: number): T {
  const [debouncedValue, setDebouncedValue] = useState<T>(value);

  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedValue(value);
    }, delay);

    return () => {
      clearTimeout(handler);
    };
  }, [value, delay]);

  return debouncedValue;
}

// File upload hook
export function useFileUpload() {
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const uploadFile = useCallback(async (file: File) => {
    try {
      setUploading(true);
      setError(null);
      
      const result = await api.uploadFile(file);
      return result;
    } catch (err) {
      const errorMessage = handleAPIError(err as APIError);
      setError(errorMessage);
      throw new Error(errorMessage);
    } finally {
      setUploading(false);
    }
  }, []);

  return {
    uploading,
    error,
    uploadFile
  };
}

// Notification hook
export function useNotifications() {
  const [notifications, setNotifications] = useState<Array<{
    id: string;
    type: 'success' | 'error' | 'warning' | 'info';
    title: string;
    message: string;
    timestamp: Date;
  }>>([]);

  const addNotification = useCallback((
    type: 'success' | 'error' | 'warning' | 'info',
    title: string,
    message: string
  ) => {
    const id = Math.random().toString(36).substr(2, 9);
    const notification = {
      id,
      type,
      title,
      message,
      timestamp: new Date()
    };
    
    setNotifications(prev => [notification, ...prev.slice(0, 4)]); // Keep only 5 notifications
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
      setNotifications(prev => prev.filter(n => n.id !== id));
    }, 5000);
  }, []);

  const removeNotification = useCallback((id: string) => {
    setNotifications(prev => prev.filter(n => n.id !== id));
  }, []);

  const clearAll = useCallback(() => {
    setNotifications([]);
  }, []);

  return {
    notifications,
    addNotification,
    removeNotification,
    clearAll
  };
}