'use client';

import { useState, useEffect } from 'react';
import { api } from '@/lib/api';
import { SystemStatus, Metrics, ExecutionFeedback } from '@/types/api';
import DashboardLayout from '@/components/DashboardLayout';
import MetricsCard from '@/components/MetricsCard';
import SystemStatus from '@/components/SystemStatus';
import RecentActivity from '@/components/RecentActivity';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Badge } from '@/components/ui/badge';
import { RefreshCw, Activity, BarChart3, Settings, Zap } from 'lucide-react';
import SystemStatus from '@/components/SystemStatus';

export default function Dashboard() {
  const [systemStatus, setSystemStatus] = useState<SystemStatus | null>(null);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [recentFeedback, setRecentFeedback] = useState<ExecutionFeedback[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchData = async () => {
    try {
      setLoading(true);
      setError(null);

      // Fetch all data in parallel
      const [statusResponse, metricsResponse, feedbackResponse] = await Promise.all([
        api.getSystemStatus(),
        api.getMetrics(7),
        api.getRecentFeedback(10)
      ]);

      if (statusResponse.data) setSystemStatus(statusResponse.data);
      if (metricsResponse.data) setMetrics(metricsResponse.data);
      if (feedbackResponse.data) setRecentFeedback(feedbackResponse.data);

      if (statusResponse.error || metricsResponse.error || feedbackResponse.error) {
        setError('Some data could not be loaded');
      }

    } catch (err: any) {
      setError(err.message || 'Failed to fetch data');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    
    // Auto-refresh every 30 seconds
    const interval = setInterval(fetchData, 30000);
    return () => clearInterval(interval);
  }, []);

  if (loading && !systemStatus && !metrics) {
    return (
      <DashboardLayout>
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
        </div>
      </DashboardLayout>
    );
  }

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold tracking-tight">Multi-Agent CTF System</h1>
            <p className="text-muted-foreground">
              Real-time monitoring and analytics dashboard
            </p>
          </div>
          <div className="flex items-center space-x-4">
            <Button
              onClick={fetchData}
              disabled={loading}
              variant="outline"
              size="sm"
            >
              <RefreshCw className={`w-4 h-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
            <div className="text-sm text-muted-foreground">
              Last updated: {new Date().toLocaleTimeString()}
            </div>
          </div>
        </div>

        {/* Key Metrics */}
        {metrics && (
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <MetricsCard
              title="Success Rate"
              value={`${metrics.overall_success_rate.toFixed(1)}%`}
              description="Overall system performance"
              trend={{
                value: metrics.trend_strength * 100,
                direction: metrics.trend_direction === 'improving' ? 'up' : 
                         metrics.trend_direction === 'declining' ? 'down' : 'stable'
              }}
              variant={metrics.overall_success_rate > 80 ? 'success' : 
                      metrics.overall_success_rate > 60 ? 'warning' : 'destructive'}
            />
            <MetricsCard
              title="Avg Response Time"
              value={`${metrics.avg_response_time.toFixed(2)}s`}
              description="Average execution time"
              variant={metrics.avg_response_time < 3 ? 'success' : 
                      metrics.avg_response_time < 5 ? 'warning' : 'destructive'}
            />
            <MetricsCard
              title="Total Executions"
              value={metrics.total_executions}
              description="Challenges processed"
            />
            <MetricsCard
              title="Confidence Score"
              value={`${(metrics.avg_confidence * 100).toFixed(0)}%`}
              description="Average system confidence"
              variant={metrics.avg_confidence > 0.8 ? 'success' : 
                      metrics.avg_confidence > 0.6 ? 'warning' : 'destructive'}
            />
          </div>
        )}

        {/* Main Content Tabs */}
        <Tabs defaultValue="overview" className="space-y-4">
          <TabsList>
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="performance">Performance</TabsTrigger>
            <TabsTrigger value="agents">Agents</TabsTrigger>
          </TabsList>

          <TabsContent value="overview" className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2">
              {/* System Status */}
              {systemStatus && (
                <SystemStatus status={systemStatus} />
              )}

              {/* Recent Activity */}
              <RecentActivity executions={recentFeedback} />
            </div>

            {/* Challenge Type Performance */}
            {metrics && metrics.success_by_type && (
              <Card>
                <CardHeader>
                  <CardTitle>Performance by Challenge Type</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
                    {Object.entries(metrics.success_by_type).map(([type, rate]) => (
                      <div key={type} className="space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-sm font-medium">{type}</span>
                          <Badge variant={rate > 80 ? 'success' : rate > 60 ? 'warning' : 'destructive'}>
                            {rate.toFixed(1)}%
                          </Badge>
                        </div>
                        <div className="w-full bg-secondary rounded-full h-2">
                          <div 
                            className="bg-primary h-2 rounded-full transition-all duration-300"
                            style={{ width: `${rate}%` }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          <TabsContent value="performance" className="space-y-4">
            {/* Performance Metrics */}
            {metrics && (
              <div className="grid gap-4 md:grid-cols-2">
                <Card>
                  <CardHeader>
                    <CardTitle>Response Time by Type</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-3">
                      {Object.entries(metrics.time_by_type).map(([type, time]) => (
                        <div key={type} className="flex items-center justify-between">
                          <span className="text-sm">{type}</span>
                          <span className="text-sm font-medium">{time.toFixed(2)}s</span>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle>System Recommendations</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {metrics.recommendations.map((rec, index) => (
                        <div key={index} className="text-sm p-2 bg-muted rounded">
                          {rec}
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              </div>
            )}
          </TabsContent>

          <TabsContent value="agents" className="space-y-4">
            {/* Agent Performance */}
            {metrics && metrics.agent_performance && (
              <div className="grid gap-4 md:grid-cols-3">
                {Object.entries(metrics.agent_performance).map(([agent, performance]) => (
                  <Card key={agent}>
                    <CardHeader>
                      <CardTitle className="capitalize flex items-center">
                        <Activity className="w-5 h-5 mr-2" />
                        {agent} Agent
                      </CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-2">
                        {Object.entries(performance).map(([metric, value]) => (
                          <div key={metric} className="flex justify-between">
                            <span className="text-sm text-muted-foreground capitalize">
                              {metric.replace('_', ' ')}
                            </span>
                            <span className="text-sm font-medium">
                              {typeof value === 'number' ? value.toFixed(2) : value}
                            </span>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}
          </TabsContent>
        </Tabs>

        {/* Error Display */}
        {error && (
          <Card className="border-destructive">
            <CardContent className="pt-6">
              <div className="flex items-center space-x-2 text-destructive">
                <span>{error}</span>
                <Button onClick={fetchData} variant="outline" size="sm">
                  Retry
                </Button>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </DashboardLayout>
  );
}