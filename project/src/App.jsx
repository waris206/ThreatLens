import { useState } from 'react';
import Navbar from './components/Navbar';
import FileUploadZone from './components/FileUploadZone';
import FileDetailsCard from './components/FileDetailsCard';
import LiveTerminal from './components/LiveTerminal';
import InvestigationTimeline from './components/InvestigationTimeline';
import AdminPortal from './components/admin/AdminPortal';

function App() {
  const [uploadedFile, setUploadedFile] = useState(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [currentStage, setCurrentStage] = useState(null);
  const [analysisMode, setAnalysisMode] = useState('v2');
  const [inputType, setInputType] = useState('file');
  const [adminOpen, setAdminOpen] = useState(false);

  const handleFileUpload = async (file) => {
    setIsAnalyzing(true);
    setCurrentStage('upload');

    const formData = new FormData();
    formData.append('file', file);
    formData.append('mode', analysisMode);

    try {
      const apiUrl = import.meta.env.VITE_API_URL || 'http://localhost:5000';
      const endpoint = inputType === 'email' ? '/analyze/email' : '/upload';
      const response = await fetch(`${apiUrl}${endpoint}`, {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`Upload failed: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();

      if (data.success && data.email) {
        setUploadedFile({
          name: file.name,
          size: file.size,
          analysisId: data.analysisId,
          emailAnalysis: data.email,
          riskScore: {
            score: data.email.overallRisk,
            label: data.classification,
            breakdown: [
              {
                signal: 'EMAIL_AGGREGATED_RISK',
                delta: data.email.overallRisk,
                reason: `${data.email.suspiciousAttachments} suspicious attachment(s), ${data.email.suspiciousUrls} suspicious URL(s)`,
              },
            ],
          },
        });
        setTimeout(() => setCurrentStage('hashed'), 500);
        setTimeout(() => setCurrentStage('metadata'), 1500);
        setTimeout(() => setCurrentStage('stego'), 2500);
        setTimeout(() => {
          setCurrentStage('report');
          setIsAnalyzing(false);
        }, 3500);
      } else if (data.success && data.file) {
        // Capture sha256, entropy, magic bytes, VirusTotal, strings, and metadata from backend response
        setUploadedFile({
          analysisId: data.file.analysisId,
          timestamp: data.file.timestamp,
          name: data.file.name,
          size: data.file.size,
          sha256: data.file.sha256,
          entropy: data.file.entropy,
          magicBytes: data.file.magicBytes,
          virusTotal: data.file.virusTotal,
          yaraify: data.file.yaraify,
          malwareBazaar: data.file.malwareBazaar,
          sandbox: data.file.sandbox,
          extractedStrings: data.file.extractedStrings,
          fileMetadata: data.file.fileMetadata,
          peAnalysis: data.file.peAnalysis,
          yaraHits: data.file.yaraHits,
          digitalSignature: data.file.digitalSignature,
          riskScore: data.file.riskScore,
        });

        setTimeout(() => setCurrentStage('hashed'), 500);
        setTimeout(() => setCurrentStage('metadata'), 2000);
        setTimeout(() => setCurrentStage('stego'), 3500);
        setTimeout(() => {
          setCurrentStage('report');
          setIsAnalyzing(false);
        }, 5500);
      } else {
        throw new Error('Upload response missing success or file data');
      }
    } catch (error) {
      console.error('Upload failed:', error);
      setIsAnalyzing(false);
      setCurrentStage(null);
      alert(`Upload failed: ${error.message}`);
    }
  };

  const handleReset = () => {
    setUploadedFile(null);
    setIsAnalyzing(false);
    setCurrentStage(null);
  };

  return (
    <div className="min-h-screen bg-slate-950 flex flex-col">
      <Navbar onOpenAdmin={() => setAdminOpen(true)} />

      <main className="flex-1 container mx-auto px-6 py-8">
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
          <div className="lg:col-span-2 space-y-6">
            {!uploadedFile ? (
              <FileUploadZone
                onFileUpload={handleFileUpload}
                analysisMode={analysisMode}
                onModeChange={setAnalysisMode}
                inputType={inputType}
                onInputTypeChange={setInputType}
              />
            ) : (
              <div className="space-y-4">
                <FileDetailsCard file={uploadedFile} />
                <button
                  onClick={handleReset}
                  className="w-full px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg border border-zinc-700 transition-colors text-sm"
                >
                  Analyze Another File
                </button>
              </div>
            )}
          </div>

          <div className="lg:col-span-1">
            <LiveTerminal
              isActive={isAnalyzing}
              analysisMode={analysisMode}
            />
          </div>
        </div>

        <InvestigationTimeline currentStage={currentStage} />
      </main>

      <footer className="border-t border-zinc-800 bg-slate-900 px-6 py-4">
        <div className="container mx-auto flex items-center justify-between text-xs text-slate-500">
          <div>
            ThreatLens v2.0.0 — AI-Driven Malware Triage
          </div>
          <div className="flex items-center space-x-4">
            <span>{analysisMode === 'v2' ? '4 Swarm Agents' : 'Quick Triage'}</span>
            <span>•</span>
            <span>Deep Swarm Inspection</span>
          </div>
        </div>
      </footer>

      {adminOpen && <AdminPortal onClose={() => setAdminOpen(false)} />}
    </div>
  );
}

export default App;
