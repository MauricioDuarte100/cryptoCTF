'use client';

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { ExecutionFeedback } from '@/types/api';
import { CheckCircle, XCircle, Clock, Zap } from 'lucide-react';
import { formatTime, getChallengeTypeColor } from '@/lib/api';

interface RecentActivityProps {
  executions: ExecutionFeedback[];
}

export default function RecentActivity({ executions }: RecentActivityProps) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Recent Activity</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {executions.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              No recent executions
            </div>
          ) : (
            executions.map((execution, index) => (
              <div key={index} className="flex items-start space-x-3 pb-3 border-b last:border-b-0">
                <div className="flex-shrink-0 mt-1">
                  {execution.success ? (
                    <CheckCircle className="w-5 h-5 text-green-500" />
                  ) : (
                    <XCircle className="w-5 h-5 text-red-500" />
                  )}
                </div>
                
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between">
                    <p className="text-sm font-medium truncate">
                      {execution.challenge_name}
                    </p>
                    <div className="flex items-center space-x-2">
                      <Badge 
                        variant="outline" 
                        className={getChallengeTypeColor(execution.challenge_type)}
                      >
                        {execution.challenge_type}
                      </Badge>
                    </div>
                  </div>
                  
                  <div className="flex items-center space-x-4 mt-1 text-xs text-muted-foreground">
                    <div className="flex items-center space-x-1">
                      <Clock className="w-3 h-3" />
                      <span>{formatTime(execution.total_time)}</span>
                    </div>
                    <div className="flex items-center space-x-1">
                      <Zap className="w-3 h-3" />
                      <span>{(execution.confidence * 100).toFixed(0)}%</span>
                    </div>
                    <span>{new Date(execution.timestamp).toLocaleTimeString()}</span>
                  </div>
                  
                  {execution.flag_found && (
                    <div className="mt-2 p-2 bg-green-50 rounded text-xs font-mono text-green-800">
                      {execution.flag_found}
                    </div>
                  )}
                </div>
              </div>
            ))
          )}
        </div>
      </CardContent>
    </Card>
  );
}