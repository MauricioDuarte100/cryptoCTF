'use client';

import React, { useState } from 'react';
import { Card, CardHeader, CardContent } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { LoadingSpinner } from '@/components/ui/LoadingSpinner';
import { useSystemStatus, useChallengeSolver, useNotifications } from '@/hooks/useAPI';
import { ChallengeFile } from '@/types/api';
import { 
  CpuChipIcon, 
  DocumentTextIcon, 
  ChartBarIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ClockIcon,
  CogIcon,
  PlayIcon,
  DocumentArrowUpIcon
} from '@heroicons/react/24/outline';

// System Status Component
const SystemStatus: React.FC = () => {
  const { status, loading, error } = useSystemStatus();

  if (loading) {
    return (
      <Card>
        <CardContent>
          <div className="flex items-center justify-center py-8">
            <LoadingSpinner size="lg" />
          </div>
        </CardContent>
      </Card>
    );
  }

  if (error) {
    return (
      <Card variant="bordered">
        <CardContent>
          <div className="flex items-center text-red-600">
            <ExclamationTriangleIcon className="h-5 w-5 mr-2" />
            <span>Failed to load system status: {error}</span>
          </div>
        </CardContent>
      </Card>
    );
  }

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'operational': return 'text-green-600 bg-green-100';
      case 'degraded': return 'text-yellow-600 bg-yellow-100';
      default: return 'text-red-600 bg-red-100';
    }
  };

  return (
    <Card>
      <CardHeader title="System Status" />
      <CardContent>
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <span className="font-medium">Overall Status</span>
            <span className={`px-3 py-1 rounded-full text-sm font-medium ${getStatusColor(status?.status || 'down')}`}>
              {status?.status || 'Unknown'}
            </span>
          </div>
          
          <div className="grid grid-cols-2 gap-4">
            {Object.entries(status?.components || {}).map(([component, available]) => (
              <div key={component} className="flex items-center justify-between">
                <span className="text-sm text-gray-600 capitalize">
                  {component.replace('_', ' ')}
                </span>
                <span className={`text-sm font-medium ${available ? 'text-green-600' : 'text-red-600'}`}>
                  {available ? '✓' : '✗'}
                </span>
              </div>
            ))}
          </div>
          
          {status?.capabilities && status.capabilities.length > 0 && (
            <div>
              <h4 className="font-medium text-gray-900 mb-2">Capabilities</h4>
              <div className="flex flex-wrap gap-2">
                {status.capabilities.map((capability, index) => (
                  <span
                    key={index}
                    className="px-2 py-1 bg-blue-100 text-blue-800 text-xs rounded-full"
                  >
                    {capability}
                  </span>
                ))}
              </div>
            </div>
          )}
          
          {status?.statistics && (
            <div className="grid grid-cols-2 gap-4 pt-4 border-t">
              <div>
                <span className="text-sm text-gray-600">Total Requests</span>
                <p className="text-lg font-semibold">{status.statistics.total_requests}</p>
              </div>
              <div>
                <span className="text-sm text-gray-600">Success Rate</span>
                <p className="text-lg font-semibold">
                  {status.statistics.total_requests > 0 
                    ? `${((status.statistics.successful_solves / status.statistics.total_requests) * 100).toFixed(1)}%`
                    : 'N/A'
                  }
                </p>
              </div>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};

// Challenge Solver Component
const ChallengeSolver: React.FC = () => {
  const { solving, result, error, solveChallenge, reset } = useChallengeSolver();
  const { addNotification } = useNotifications();
  
  const [description, setDescription] = useState('');
  const [files, setFiles] = useState<ChallengeFile[]>([]);
  const [useEnhanced, setUseEnhanced] = useState(true);

  const handleAddFile = () => {
    setFiles([...files, { name: '', content: '' }]);
  };

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const uploadedFiles = event.target.files;
    if (!uploadedFiles) return;

    for (let i = 0; i < uploadedFiles.length; i++) {
      const file = uploadedFiles[i];
      const content = await file.text();
      
      setFiles(prev => [...prev, {
        name: file.name,
        content: content
      }]);
    }
    
    // Reset input
    event.target.value = '';
  };

  const handleFileChange = (index: number, field: 'name' | 'content', value: string) => {
    const newFiles = [...files];
    newFiles[index][field] = value;
    setFiles(newFiles);
  };

  const handleRemoveFile = (index: number) => {
    setFiles(files.filter((_, i) => i !== index));
  };

  const handleSolve = async () => {
    if (!description.trim()) {
      addNotification('error', 'Error', 'Please provide a challenge description');
      return;
    }

    try {
      const request = {
        description: description.trim(),
        files: files.filter(f => f.name.trim() && f.content.trim()),
        use_enhanced: useEnhanced
      };

      await solveChallenge(request);
      addNotification('success', 'Challenge Submitted', 'Challenge solving started');
    } catch (err) {
      addNotification('error', 'Solve Failed', error || 'Unknown error occurred');
    }
  };

  const handleReset = () => {
    reset();
    setDescription('');
    setFiles([]);
  };

  return (
    <Card>
      <CardHeader title="Challenge Solver" />
      <CardContent>
        <div className="space-y-4">
          {/* Description Input */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-2">
              Challenge Description
            </label>
            <textarea
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Describe the CTF challenge..."
              className="textarea min-h-[100px]"
              disabled={solving}
            />
          </div>

          {/* Files Section */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="block text-sm font-medium text-gray-700">
                Challenge Files
              </label>
              <div className="flex space-x-2">
                <input
                  type="file"
                  multiple
                  accept=".py,.json,.txt,.md"
                  onChange={handleFileUpload}
                  disabled={solving}
                  className="hidden"
                  id="file-upload"
                />
                <label
                  htmlFor="file-upload"
                  className="cursor-pointer inline-flex items-center px-3 py-1.5 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-primary-500 disabled:opacity-50"
                >
                  <DocumentArrowUpIcon className="h-4 w-4 mr-1" />
                  Upload Files
                </label>
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={handleAddFile}
                  disabled={solving}
                  icon={DocumentTextIcon}
                >
                  Add Manual
                </Button>
              </div>
            </div>
            
            {files.map((file, index) => (
              <div key={index} className="border border-gray-200 rounded-lg p-4 mb-3">
                <div className="flex items-center justify-between mb-2">
                  <input
                    type="text"
                    value={file.name}
                    onChange={(e) => handleFileChange(index, 'name', e.target.value)}
                    placeholder="filename.py"
                    className="input flex-1 mr-2"
                    disabled={solving}
                  />
                  <Button
                    size="sm"
                    variant="error"
                    onClick={() => handleRemoveFile(index)}
                    disabled={solving}
                  >
                    Remove
                  </Button>
                </div>
                <textarea
                  value={file.content}
                  onChange={(e) => handleFileChange(index, 'content', e.target.value)}
                  placeholder="File content..."
                  className="textarea min-h-[120px]"
                  disabled={solving}
                />
              </div>
            ))}
          </div>

          {/* Options */}
          <div className="flex items-center">
            <input
              type="checkbox"
              id="useEnhanced"
              checked={useEnhanced}
              onChange={(e) => setUseEnhanced(e.target.checked)}
              disabled={solving}
              className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
            />
            <label htmlFor="useEnhanced" className="ml-2 text-sm text-gray-700">
              Use Enhanced Multi-Agent System
            </label>
          </div>

          {/* Action Buttons */}
          <div className="flex space-x-3">
            <Button
              onClick={handleSolve}
              loading={solving}
              disabled={!description.trim() || solving}
              icon={PlayIcon}
              fullWidth
            >
              {solving ? 'Solving...' : 'Solve Challenge'}
            </Button>
            
            {(result || error) && (
              <Button
                variant="secondary"
                onClick={handleReset}
                disabled={solving}
              >
                Reset
              </Button>
            )}
          </div>

          {/* Results */}
          {error && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-4">
              <div className="flex items-center">
                <ExclamationTriangleIcon className="h-5 w-5 text-red-600 mr-2" />
                <span className="text-red-800 font-medium">Error</span>
              </div>
              <p className="text-red-700 mt-1">{error}</p>
            </div>
          )}

          {result && (
            <div className={`border rounded-lg p-4 ${result.success ? 'bg-green-50 border-green-200' : 'bg-yellow-50 border-yellow-200'}`}>
              <div className="flex items-center mb-3">
                {result.success ? (
                  <CheckCircleIcon className="h-5 w-5 text-green-600 mr-2" />
                ) : (
                  <ExclamationTriangleIcon className="h-5 w-5 text-yellow-600 mr-2" />
                )}
                <span className={`font-medium ${result.success ? 'text-green-800' : 'text-yellow-800'}`}>
                  {result.success ? 'Challenge Solved!' : 'Challenge Not Solved'}
                </span>
              </div>
              
              <div className="space-y-2 text-sm">
                {result.flag && (
                  <div>
                    <span className="font-medium">Flag: </span>
                    <code className="bg-gray-100 px-2 py-1 rounded font-mono">{result.flag}</code>
                  </div>
                )}
                
                {result.challenge_type && (
                  <div>
                    <span className="font-medium">Type: </span>
                    <span className="px-2 py-1 bg-blue-100 text-blue-800 rounded text-xs">
                      {result.challenge_type}
                    </span>
                  </div>
                )}
                
                {result.strategy && (
                  <div>
                    <span className="font-medium">Strategy: </span>
                    <span>{result.strategy}</span>
                  </div>
                )}
                
                <div className="flex items-center space-x-4 text-gray-600">
                  <div className="flex items-center">
                    <ClockIcon className="h-4 w-4 mr-1" />
                    <span>{result.time_taken.toFixed(2)}s</span>
                  </div>
                  
                  {result.confidence > 0 && (
                    <div>
                      <span>Confidence: {(result.confidence * 100).toFixed(1)}%</span>
                    </div>
                  )}
                  
                  {result.agents_used.length > 0 && (
                    <div>
                      <span>Agents: {result.agents_used.join(', ')}</span>
                    </div>
                  )}
                </div>
                
                {result.error && (
                  <div className="text-red-600">
                    <span className="font-medium">Error: </span>
                    <span>{result.error}</span>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};

// Main Page Component
export default function HomePage() {
  return (
    <div className="min-h-screen bg-gray-50">
      {/* Header */}
      <header className="bg-white shadow-sm border-b">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center">
              <CpuChipIcon className="h-8 w-8 text-primary-600 mr-3" />
              <div>
                <h1 className="text-xl font-bold text-gray-900">Enhanced CTF Solver</h1>
                <p className="text-sm text-gray-600">Multi-Agent AI System v3.0</p>
              </div>
            </div>
            
            <div className="flex items-center space-x-4">
              <Button variant="ghost" size="sm" icon={ChartBarIcon}>
                Statistics
              </Button>
              <Button variant="ghost" size="sm" icon={DocumentTextIcon}>
                History
              </Button>
              <Button variant="ghost" size="sm" icon={CogIcon}>
                Settings
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Left Column - Challenge Solver */}
          <div className="lg:col-span-2">
            <ChallengeSolver />
          </div>
          
          {/* Right Column - System Status */}
          <div className="space-y-6">
            <SystemStatus />
            
            {/* Quick Stats */}
            <Card>
              <CardHeader title="Quick Stats" />
              <CardContent>
                <div className="text-center text-gray-600">
                  <p className="text-sm">More detailed statistics and history will be available in the full dashboard.</p>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="bg-white border-t mt-12">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
          <div className="text-center text-sm text-gray-600">
            <p>Enhanced CTF Solver v3.0 - Advanced Multi-Agent System with BERT + RAG</p>
            <p className="mt-1">Built with Next.js, FastAPI, and AI/ML technologies</p>
          </div>
        </div>
      </footer>
    </div>
  );
}