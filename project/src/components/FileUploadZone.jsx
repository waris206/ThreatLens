import { useState } from 'react';
import { Upload, FileIcon, Zap, ShieldCheck, Mail } from 'lucide-react';

const FileUploadZone = ({ onFileUpload, analysisMode, onModeChange, inputType, onInputTypeChange }) => {
  const [isDragging, setIsDragging] = useState(false);

  const handleDragOver = (e) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e) => {
    e.preventDefault();
    setIsDragging(false);

    const files = e.dataTransfer.files;
    if (files.length > 0) {
      onFileUpload(files[0]);
    }
  };

  const handleFileInput = (e) => {
    const files = e.target.files;
    if (files.length > 0) {
      onFileUpload(files[0]);
    }
  };

  return (
    <div className="space-y-4">
      {/* Mode Toggle */}
      <div className="bg-slate-900/50 border border-zinc-800 rounded-lg p-4">
        <div className="grid grid-cols-2 gap-2 mb-4">
          <button
            onClick={() => onInputTypeChange('file')}
            className={`flex items-center justify-center gap-2 px-4 py-2 rounded border text-sm font-medium ${
              inputType === 'file'
                ? 'bg-cyber-blue/15 border-cyber-blue text-cyber-blue'
                : 'bg-slate-800/50 border-zinc-700 text-slate-400 hover:text-slate-300'
            }`}
          >
            <FileIcon className="w-4 h-4" />
            File
          </button>
          <button
            onClick={() => onInputTypeChange('email')}
            className={`flex items-center justify-center gap-2 px-4 py-2 rounded border text-sm font-medium ${
              inputType === 'email'
                ? 'bg-cyber-green/15 border-cyber-green text-cyber-green'
                : 'bg-slate-800/50 border-zinc-700 text-slate-400 hover:text-slate-300'
            }`}
          >
            <Mail className="w-4 h-4" />
            Email (.eml)
          </button>
        </div>

        <div className="flex items-center justify-between mb-3">
          <span className="text-sm font-medium text-slate-300">Analysis Mode</span>
          <span className="text-xs text-slate-500">
            {analysisMode === 'v2' ? 'Multi-Agent Deep Scan' : 'Single-Pass Quick Scan'}
          </span>
        </div>
        <div className="grid grid-cols-2 gap-2">
          <button
            onClick={() => onModeChange('v1')}
            className={`flex items-center justify-center gap-2 px-4 py-3 rounded-lg text-sm font-medium transition-all duration-200 border ${
              analysisMode === 'v1'
                ? 'bg-cyber-blue/15 border-cyber-blue text-cyber-blue shadow-[0_0_10px_rgba(0,217,255,0.15)]'
                : 'bg-slate-800/50 border-zinc-700 text-slate-400 hover:border-zinc-600 hover:text-slate-300'
            }`}
          >
            <Zap className="w-4 h-4" />
            Quick Triage (v1)
          </button>
          <button
            onClick={() => onModeChange('v2')}
            className={`flex items-center justify-center gap-2 px-4 py-3 rounded-lg text-sm font-medium transition-all duration-200 border ${
              analysisMode === 'v2'
                ? 'bg-cyber-green/15 border-cyber-green text-cyber-green shadow-[0_0_10px_rgba(0,255,65,0.15)]'
                : 'bg-slate-800/50 border-zinc-700 text-slate-400 hover:border-zinc-600 hover:text-slate-300'
            }`}
          >
            <ShieldCheck className="w-4 h-4" />
            Deep Swarm (v2)
          </button>
        </div>
        {analysisMode === 'v2' && (
          <p className="text-xs text-slate-500 mt-2">
            3 AI agents will analyse sequentially: Static Analyst → Threat OSINT → Lead Investigator
          </p>
        )}
      </div>

      {/* Upload Zone */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={`
          relative border-2 border-dashed rounded-lg p-12
          transition-all duration-300 ease-in-out cursor-pointer
          ${isDragging
            ? 'border-cyber-green bg-cyber-green/5 shadow-neon-green'
            : 'border-zinc-700 hover:border-zinc-600 bg-slate-900/50'
          }
        `}
      >
        <input
          type="file"
          id="file-upload"
          className="hidden"
          onChange={handleFileInput}
        />

        <label htmlFor="file-upload" className="cursor-pointer">
          <div className="flex flex-col items-center space-y-4">
            <div className={`
              p-6 rounded-full border-2 transition-all duration-300
              ${isDragging
                ? 'border-cyber-green bg-cyber-green/10'
                : 'border-zinc-700 bg-slate-800'
              }
            `}>
              <Upload
                className={`w-12 h-12 transition-colors duration-300 ${
                  isDragging ? 'text-cyber-green' : 'text-slate-400'
                }`}
              />
            </div>

            <div className="text-center">
              <h3 className="text-xl font-semibold text-slate-200 mb-2">
                {inputType === 'email' ? 'Drop Email to Analyze' : 'Drop File to Analyze'}
              </h3>
              <p className="text-sm text-slate-400">
                or click to browse your files
              </p>
              <p className="text-xs text-slate-500 mt-3">
                {inputType === 'email'
                  ? 'Supported: RFC 822 .eml messages with attachments'
                  : 'Supported: Images, Documents, Executables, Archives (Max 10MB)'}
              </p>
            </div>

            <div className="flex items-center space-x-2 text-xs text-slate-500">
              <FileIcon className="w-4 h-4" />
              <span>Ready for forensic analysis</span>
            </div>
          </div>
        </label>
      </div>
    </div>
  );
};

export default FileUploadZone;
