// API Types for Enhanced CTF Solver

export interface ChallengeFile {
  name: string;
  content: string;
}

export interface SolveRequest {
  description: string;
  files: ChallengeFile[];
  host?: string;
  port?: number;
  use_enhanced?: boolean;
}

export interface SolveResponse {
  success: boolean;
  flag?: string;
  challenge_type?: string;
  confidence: number;
  time_taken: number;
  strategy?: string;
  agents_used: string[];
  rag_context?: {
    available: boolean;
    total_retrieved: number;
    strategies: string[];
    similar_writeups: Array<{
      title: string;
      attack_type: string;
      similarity: number;
      url?: string;
    }>;
  };
  error?: string;
  enhanced_features: Record<string, boolean>;
}

export interface SystemStatus {
  status: string;
  components: Record<string, boolean>;
  capabilities: string[];
  statistics: {
    total_requests: number;
    successful_solves: number;
    average_time: number;
    uptime: string;
    rag_writeups?: number;
  };
}

export interface ClassificationResponse {
  success: boolean;
  challenge_type?: string;
  confidence?: number;
  method: string;
  error?: string;
}

export interface RAGSearchResponse {
  success: boolean;
  results?: Array<{
    title: string;
    attack_type: string;
    similarity: number;
    content_preview: string;
    url?: string;
  }>;
  total?: number;
  error?: string;
}

export interface HistoryEntry {
  timestamp: string;
  description: string;
  success: boolean;
  flag?: string;
  challenge_type?: string;
  time_taken: number;
  strategy?: string;
  enhanced_used: boolean;
}

export interface HistoryResponse {
  success: boolean;
  history: HistoryEntry[];
  total: number;
  error?: string;
}

export interface Statistics {
  total_requests: number;
  successful_solves: number;
  success_rate: number;
  average_time: number;
  challenge_types: Record<string, {
    total: number;
    successful: number;
  }>;
  strategies_used: Record<string, {
    total: number;
    successful: number;
  }>;
  recent_performance: Array<{
    timestamp: string;
    success: boolean;
    time_taken: number;
    challenge_type?: string;
  }>;
}

export interface StatisticsResponse {
  success: boolean;
  statistics?: Statistics;
  error?: string;
}

export interface UploadResponse {
  success: boolean;
  filename?: string;
  content?: string;
  size?: number;
  error?: string;
}

// UI State Types
export interface UIState {
  isLoading: boolean;
  error?: string;
  success?: string;
}

export interface ChallengeFormData {
  description: string;
  files: ChallengeFile[];
  useEnhanced: boolean;
}

// Chart Data Types
export interface ChartData {
  name: string;
  value: number;
  color?: string;
}

export interface TimeSeriesData {
  timestamp: string;
  success: number;
  time_taken: number;
}

// Component Props Types
export interface MetricCardProps {
  title: string;
  value: string | number;
  subtitle?: string;
  icon?: React.ComponentType<any>;
  color?: 'blue' | 'green' | 'yellow' | 'red' | 'purple';
  trend?: {
    value: number;
    isPositive: boolean;
  };
}

export interface StatusIndicatorProps {
  status: 'operational' | 'degraded' | 'down';
  label: string;
}

export interface LoadingSpinnerProps {
  size?: 'sm' | 'md' | 'lg';
  color?: string;
}

// Error Types
export interface APIError {
  message: string;
  status?: number;
  details?: any;
}

// Notification Types
export interface Notification {
  id: string;
  type: 'success' | 'error' | 'warning' | 'info';
  title: string;
  message: string;
  timestamp: Date;
  duration?: number;
}