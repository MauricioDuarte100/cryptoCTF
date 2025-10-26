'use client';

import { useState } from 'react';
import { api } from '@/lib/api';
import { ChallengeRequest, ChallengeResponse } from '@/types/api';
import DashboardLayout from '@/components/DashboardLayout';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Textarea } from '@/components/ui/textarea';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Play, Plus, X, CheckCircle, XCircle, Clock, Zap } from 'lucide-react';
import { formatTime } from '@/lib/api';

interface FileInput {
  name: string;
  content: string;
}

export default function ChallengePage() {
  const [description, setDescription] = useState('');
  const [files, setFiles] = useState<FileInput[]>([{ name: '', content: '' }]);
  const [maxTime, setMaxTime] = useState(60);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ChallengeResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const addFile = () => {
    setFiles([...files, { name: '', content: '' }]);
  };

  const removeFile = (index: number) => {
    if (files.length > 1) {
      setFiles(files.filter((_, i) => i !== index));
    }
  };

  const updateFile = (index: number, field: 'name' | 'content', value: string) => {
    const newFiles = [...files];
    newFiles[index][field] = value;
    setFiles(newFiles);
  };

  const executeChallenge = async () => {
    if (!description.trim()) {
      setError('Please provide a challenge description');
      return;
    }

    const validFiles = files.filter(f => f.name.trim() && f.content.trim());
    if (validFiles.length === 0) {
      setError('Please provide at least one file');
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const request: ChallengeRequest = {
        description: description.trim(),
        files: validFiles.map(f => ({ name: f.name.trim(), content: f.content.trim() })),
        max_execution_time: maxTime
      };

      const response = await api.solveChallenge(request);
      
      if (response.error) {
        setError(response.error);
      } else if (response.data) {
        setResult(response.data);
      }
    } catch (err: any) {
      setError(err.message || 'Failed to execute challenge');
    } finally {
      setLoading(false);
    }
  };

  const resetForm = () => {
    setDescription('');
    setFiles([{ name: '', content: '' }]);
    setMaxTime(60);
    setResult(null);
    setError(null);
  };

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Execute Challenge</h1>
          <p className="text-muted-foreground">
            Submit a CTF challenge for the multi-agent system to solve
          </p>
        </div>

        <div className="grid gap-6 lg:grid-cols-2">
          {/* Input Form */}
          <Card>
            <CardHeader>
              <CardTitle>Challenge Input</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Description */}
              <div className="space-y-2">
                <Label htmlFor="description">Challenge Description</Label>
                <Textarea
                  id="description"
                  placeholder="Describe the CTF challenge (e.g., RSA encryption with small exponent, Caesar cipher, XOR challenge...)"
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  rows={3}
                />
              </div>

              {/* Files */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <Label>Challenge Files</Label>
                  <Button onClick={addFile} variant="outline" size="sm">
                    <Plus className="w-4 h-4 mr-2" />
                    Add File
                  </Button>
                </div>
                
                <div className="space-y-3">
                  {files.map((file, index) => (
                    <div key={index} className="space-y-2 p-3 border rounded-lg">
                      <div className="flex items-center space-x-2">
                        <Input
                          placeholder="filename.py"
                          value={file.name}
                          onChange={(e) => updateFile(index, 'name', e.target.value)}
                          className="flex-1"
                        />
                        {files.length > 1 && (
                          <Button
                            onClick={() => removeFile(index)}
                            variant="outline"
                            size="sm"
                          >
                            <X className="w-4 h-4" />
                          </Button>
                        )}
                      </div>
                      <Textarea
                        placeholder="File content..."
                        value={file.content}
                        onChange={(e) => updateFile(index, 'content', e.target.value)}
                        rows={4}
                        className="font-mono text-sm"
                      />
                    </div>
                  ))}
                </div>
              </div>

              {/* Max Time */}
              <div className="space-y-2">
                <Label htmlFor="maxTime">Max Execution Time (seconds)</Label>
                <Input
                  id="maxTime"
                  type="number"
                  min="10"
                  max="300"
                  value={maxTime}
                  onChange={(e) => setMaxTime(parseInt(e.target.value) || 60)}
                />
              </div>

              {/* Actions */}
              <div className="flex space-x-2">
                <Button
                  onClick={executeChallenge}
                  disabled={loading}
                  className="flex-1"
                >
                  {loading ? (
                    <>
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2" />
                      Executing...
                    </>
                  ) : (
                    <>
                      <Play className="w-4 h-4 mr-2" />
                      Execute Challenge
                    </>
                  )}
                </Button>
                <Button onClick={resetForm} variant="outline">
                  Reset
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Results */}
          <Card>
            <CardHeader>
              <CardTitle>Execution Results</CardTitle>
            </CardHeader>
            <CardContent>
              {loading && (
                <div className="flex items-center justify-center py-8">
                  <div className="text-center">
                    <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary mx-auto mb-4" />
                    <p className="text-muted-foreground">Multi-agent system is working...</p>
                  </div>
                </div>
              )}

              {error && (
                <div className="p-4 border border-destructive rounded-lg bg-destructive/10">
                  <div className="flex items-center space-x-2 text-destructive">
                    <XCircle className="w-5 h-5" />
                    <span className="font-medium">Error</span>
                  </div>
                  <p className="mt-2 text-sm">{error}</p>
                </div>
              )}

              {result && (
                <div className="space-y-4">
                  {/* Status */}
                  <div className="flex items-center space-x-2">
                    {result.success ? (
                      <CheckCircle className="w-6 h-6 text-green-500" />
                    ) : (
                      <XCircle className="w-6 h-6 text-red-500" />
                    )}
                    <span className="text-lg font-medium">
                      {result.success ? 'Challenge Solved!' : 'Challenge Failed'}
                    </span>
                  </div>

                  {/* Metrics */}
                  <div className="grid grid-cols-3 gap-4">
                    <div className="text-center">
                      <div className="flex items-center justify-center space-x-1 text-muted-foreground mb-1">
                        <Clock className="w-4 h-4" />
                        <span className="text-sm">Time</span>
                      </div>
                      <div className="text-lg font-medium">{formatTime(result.total_time)}</div>
                    </div>
                    <div className="text-center">
                      <div className="flex items-center justify-center space-x-1 text-muted-foreground mb-1">
                        <Zap className="w-4 h-4" />
                        <span className="text-sm">Confidence</span>
                      </div>
                      <div className="text-lg font-medium">{(result.confidence * 100).toFixed(0)}%</div>
                    </div>
                    <div className="text-center">
                      <div className="text-sm text-muted-foreground mb-1">Quality</div>
                      <div className="text-lg font-medium">{(result.quality_score * 100).toFixed(0)}%</div>
                    </div>
                  </div>

                  {/* Flag */}
                  {result.flag && (
                    <div className="p-3 bg-green-50 border border-green-200 rounded-lg">
                      <div className="text-sm font-medium text-green-800 mb-1">Flag Found:</div>
                      <div className="font-mono text-sm text-green-700 bg-green-100 p-2 rounded">
                        {result.flag}
                      </div>
                    </div>
                  )}

                  {/* Agents Used */}
                  <div>
                    <div className="text-sm font-medium mb-2">Agents Used:</div>
                    <div className="flex flex-wrap gap-2">
                      {result.agents_used.map((agent) => (
                        <Badge key={agent} variant="outline">
                          {agent}
                        </Badge>
                      ))}
                    </div>
                  </div>

                  {/* Execution ID */}
                  <div className="text-xs text-muted-foreground">
                    Execution ID: {result.execution_id}
                  </div>
                </div>
              )}

              {!loading && !error && !result && (
                <div className="text-center py-8 text-muted-foreground">
                  Submit a challenge to see results here
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </DashboardLayout>
  );
}