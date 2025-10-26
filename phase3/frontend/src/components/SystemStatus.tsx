'use client';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { SystemStatus as SystemStatusType } from '@/types/api';
import { Activity, CheckCircle, AlertCircle, XCircle } from 'lucide-react';

interface SystemStatusProps {
  status: SystemStatusType;
}

export default function SystemStatus({ status }: SystemStatusProps) {
  const getStatusIcon = (agentStatus: string) => {
    switch (agentStatus) {
      case 'active':
        return <CheckCircle className="w-4 h-4 text-green-500" />;
      case 'warning':
        return <AlertCircle className="w-4 h-4 text-yellow-500" />;
      case 'error':
        return <XCircle className="w-4 h-4 text-red-500" />;
      default:
        return <Activity className="w-4 h-4 text-gray-500" />;
    }
  };

  const getStatusBadge = (systemStatus: string) => {
    switch (systemStatus) {
      case 'operational':
        return <Badge variant="success">Operational</Badge>;
      case 'degraded':
        return <Badge variant="warning">Degraded</Badge>;
      case 'down':
        return <Badge variant="destructive">Down</Badge>;
      default:
        return <Badge variant="outline">Unknown</Badge>;
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center justify-between">
          <span>System Status</span>
          {getStatusBadge(status.system_status)}
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Overall Metrics */}
        <div className="grid grid-cols-2 gap-4">
          <div>
            <div className="text-2xl font-bold">{status.recent_executions}</div>
            <div className="text-sm text-muted-foreground">Recent Executions</div>
          </div>
          <div>
            <div className="text-2xl font-bold">{status.current_success_rate?.toFixed(1)}%</div>
            <div className="text-sm text-muted-foreground">Success Rate</div>
          </div>
        </div>

        {/* Agent Status */}
        <div className="space-y-2">
          <h4 className="text-sm font-medium">Agent Status</h4>
          <div className="grid grid-cols-2 gap-2">
            {Object.entries(status.agents_status).map(([agent, agentStatus]) => (
              <div key={agent} className="flex items-center space-x-2">
                {getStatusIcon(agentStatus)}
                <span className="text-sm capitalize">{agent}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Last Execution */}
        {status.last_execution && (
          <div>
            <div className="text-sm text-muted-foreground">Last Execution</div>
            <div className="text-sm">
              {new Date(status.last_execution).toLocaleString()}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}