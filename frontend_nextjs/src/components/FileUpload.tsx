import React, { useCallback, useState } from 'react';
import { useDropzone } from 'react-dropzone';
import { DocumentArrowUpIcon, XMarkIcon, DocumentTextIcon } from '@heroicons/react/24/outline';
import { ChallengeFile } from '@/types/api';

interface FileUploadProps {
  files: ChallengeFile[];
  onFilesChange: (files: ChallengeFile[]) => void;
  disabled?: boolean;
}

export const FileUpload: React.FC<FileUploadProps> = ({
  files,
  onFilesChange,
  disabled = false
}) => {
  const [dragActive, setDragActive] = useState(false);

  const onDrop = useCallback(async (acceptedFiles: File[]) => {
    const newFiles: ChallengeFile[] = [];
    
    for (const file of acceptedFiles) {
      try {
        const content = await file.text();
        newFiles.push({
          name: file.name,
          content: content
        });
      } catch (error) {
        console.error(`Error reading file ${file.name}:`, error);
      }
    }
    
    onFilesChange([...files, ...newFiles]);
  }, [files, onFilesChange]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    disabled,
    accept: {
      'text/plain': ['.txt', '.py', '.json', '.md', '.js', '.ts'],
      'application/json': ['.json'],
      'text/x-python': ['.py']
    },
    multiple: true
  });

  const removeFile = (index: number) => {
    const newFiles = files.filter((_, i) => i !== index);
    onFilesChange(newFiles);
  };

  const updateFile = (index: number, field: 'name' | 'content', value: string) => {
    const newFiles = [...files];
    newFiles[index][field] = value;
    onFilesChange(newFiles);
  };

  return (
    <div className="space-y-4">
      {/* Drop Zone */}
      <div
        {...getRootProps()}
        className={`
          border-2 border-dashed rounded-lg p-6 text-center cursor-pointer transition-colors
          ${isDragActive 
            ? 'border-primary-500 bg-primary-50' 
            : 'border-gray-300 hover:border-gray-400'
          }
          ${disabled ? 'opacity-50 cursor-not-allowed' : ''}
        `}
      >
        <input {...getInputProps()} />
        <DocumentArrowUpIcon className="mx-auto h-12 w-12 text-gray-400 mb-4" />
        
        {isDragActive ? (
          <p className="text-primary-600 font-medium">Drop the files here...</p>
        ) : (
          <div>
            <p className="text-gray-600 font-medium mb-2">
              Drag & drop challenge files here, or click to select
            </p>
            <p className="text-sm text-gray-500">
              Supports: .py, .json, .txt, .md files
            </p>
          </div>
        )}
      </div>

      {/* File List */}
      {files.length > 0 && (
        <div className="space-y-3">
          <h4 className="font-medium text-gray-900">Uploaded Files ({files.length})</h4>
          
          {files.map((file, index) => (
            <div key={index} className="border border-gray-200 rounded-lg p-4 bg-white">
              {/* File Header */}
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center">
                  <DocumentTextIcon className="h-5 w-5 text-gray-400 mr-2" />
                  <input
                    type="text"
                    value={file.name}
                    onChange={(e) => updateFile(index, 'name', e.target.value)}
                    className="font-medium text-gray-900 bg-transparent border-none focus:outline-none focus:ring-2 focus:ring-primary-500 rounded px-2 py-1"
                    disabled={disabled}
                  />
                </div>
                
                <button
                  onClick={() => removeFile(index)}
                  disabled={disabled}
                  className="text-gray-400 hover:text-red-500 transition-colors disabled:opacity-50"
                >
                  <XMarkIcon className="h-5 w-5" />
                </button>
              </div>

              {/* File Content */}
              <div className="relative">
                <textarea
                  value={file.content}
                  onChange={(e) => updateFile(index, 'content', e.target.value)}
                  placeholder="File content will appear here..."
                  className="w-full h-32 p-3 border border-gray-200 rounded-md font-mono text-sm resize-y focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent"
                  disabled={disabled}
                />
                
                {/* File Stats */}
                <div className="absolute bottom-2 right-2 text-xs text-gray-500 bg-white px-2 py-1 rounded">
                  {file.content.length} chars
                </div>
              </div>

              {/* File Preview */}
              {file.content.length > 0 && (
                <div className="mt-3 p-3 bg-gray-50 rounded-md">
                  <div className="text-xs text-gray-600 mb-2">Preview:</div>
                  <pre className="text-xs text-gray-800 overflow-x-auto whitespace-pre-wrap">
                    {file.content.substring(0, 200)}
                    {file.content.length > 200 && '...'}
                  </pre>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Quick Actions */}
      {files.length > 0 && (
        <div className="flex justify-between items-center text-sm text-gray-600">
          <span>{files.length} file{files.length !== 1 ? 's' : ''} ready</span>
          <button
            onClick={() => onFilesChange([])}
            disabled={disabled}
            className="text-red-600 hover:text-red-700 disabled:opacity-50"
          >
            Clear all files
          </button>
        </div>
      )}
    </div>
  );
};