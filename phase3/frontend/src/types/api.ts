// API Types for Multi-Agent CTF System

export interface ChallengeRequest {
  description: string;
  files: Array<{
    name: string;
    content: string;
  }>;
  max_execution_time?: number;
}

export interface ChallengeResponse {
  success: boolean;
  flag?: string;
  total_time: number;
  agents_used: string[];
  confidence: number;
  quality_score: number;
  execution_id: string;
}

export interface SystemStatus {
  system_status: string;
  recent_executions: number;
  current_success_rate: number;
  avg_response_time: number;
  last_execution?: string;
  agents_status: {
    planner: string;
    executor: string;
    validator: string;
    coordinator: string;
  };
}

export interface Metrics {
  overall_success_rate: number;
  avg_response_time: number;
  avg_confidence: number;
  total_executions: number;
  successful_executions: number;
  failed_executions: number;
  success_by_type: Record<string, number>;
  time_by_type: Record<string, number>;
  agent_performance: Record<string, Record<string, number>>;
  trend_direction: 'improving' | 'declining' | 'stable';
  trend_strength: number;
  recommendations: string[];
}

export interface PerformanceTrend {
  date: string;
  total_executions: number;
  successful_executions: number;
  success_rate: number;
  avg_time: number;
  avg_confidence: number;
  avg_quality: number;
}

export interface PerformanceTrends {
  daily_trends: PerformanceTrend[];
}

export interface ErrorPattern {
  errors: string[];
  warnings: string[];
  challenge_type: string;
  frequency: number;
}

export interface ErrorAnalysis {
  error_patterns: ErrorPattern[];
}

export interface ExecutionFeedback {
  timestamp: string;
  challenge_id: string;
  challenge_type: string;
  challenge_name: string;
  success: boolean;
  flag_found?: string;
  total_time: number;
  confidence: number;
  quality_score: number;
  agents_used: string[];
  planner_confidence: number;
  planner_strategies: number;
  planner_rag_patterns: number;
  executor_attempts: number;
  executor_success_strategy?: string;
  validator_confidence: number;
  strategies_tried: Array<{
    name: string;
    priority: number;
    success: boolean;
    time: number;
  }>;
  winning_strategy?: {
    name: string;
    priority: number;
    success: boolean;
    time: number;
  };
  failed_strategies: Array<{
    name: string;
    priority: number;
    success: boolean;
    time: number;
  }>;
  errors: string[];
  warnings: string[];
  rag_context: Array<{
    pattern: string;
    similarity: number;
  }>;
  bert_prediction: string;
  bert_confidence: number;
  memory_usage: number;
  cpu_usage: number;
}

export interface TuningAdjustment {
  parameter: string;
  old_value: any;
  new_value: any;
  reason: string;
}

export interface TuningResponse {
  timestamp: string;
  adjustments_made: TuningAdjustment[];
  recommendations: string[];
  performance_impact: {
    expected_success_rate_change: number;
    expected_response_time_change: number;
    confidence_level: 'low' | 'medium' | 'high';
  };
}

export interface OptimizationOpportunities {
  threshold_adjustments: Array<{
    type: string;
    current: string;
    recommended: string;
    reason: string;
  }>;
  strategy_improvements: Array<{
    challenge_type: string;
    strategies: Array<{
      name: string;
    }>;
    failure_frequency: number;
    recommendation: string;
  }>;
  model_retraining: Array<{
    model: string;
    current_accuracy: number;
    historical_accuracy: number;
    recommendation: string;
  }>;
  performance_issues: Array<{
    type: string;
    challenge_type: string;
    avg_time: number;
    max_time: number;
    occurrences: number;
    recommendation: string;
  }>;
}

export interface AdminStats {
  coordinator_stats: {
    total_executions: number;
    success_rate: number;
    average_times: {
      total: number;
      planner: number;
      executor: number;
      validator: number;
    };
    average_confidence: number;
    average_quality: number;
    agent_usage: {
      planner: number;
      executor: number;
      validator: number;
    };
  };
  total_challenges_processed: number;
  unique_challenge_types: number;
  avg_strategies_per_challenge: number;
  system_uptime: string;
  database_status: string;
}

export interface ApiResponse<T> {
  data?: T;
  error?: string;
  message?: string;
}

// Utility types
export type ChallengeType = 'RSA' | 'Classical' | 'XOR' | 'Encoding' | 'Hash' | 'Lattice' | 'ECC' | 'Unknown';
export type AgentType = 'planner' | 'executor' | 'validator' | 'coordinator';
export type TrendDirection = 'improving' | 'declining' | 'stable';