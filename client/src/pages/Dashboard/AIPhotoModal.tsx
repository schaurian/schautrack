import { useState, useRef, useCallback, useEffect } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import { estimateCalories } from '@/api/ai';
import { Button } from '@/components/ui/Button';
import { cn } from '@/lib/utils';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  onResult: (result: { calories: number; name: string; macros?: Record<string, number> }) => void;
  enabledMacros: string[];
  providerName: string | null;
}

type Mode = 'camera' | 'upload';
type Phase = 'capture' | 'loading' | 'error';

function resizeImage(file: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const img = new Image();
    const url = URL.createObjectURL(file);
    img.onload = () => {
      URL.revokeObjectURL(url);
      const maxSize = 1024;
      let { width, height } = img;
      if (width > maxSize || height > maxSize) {
        if (width > height) {
          height = Math.round(height * maxSize / width);
          width = maxSize;
        } else {
          width = Math.round(width * maxSize / height);
          height = maxSize;
        }
      }
      const canvas = document.createElement('canvas');
      canvas.width = width;
      canvas.height = height;
      const ctx = canvas.getContext('2d');
      if (!ctx) { reject(new Error('No canvas context')); return; }
      ctx.drawImage(img, 0, 0, width, height);
      resolve(canvas.toDataURL('image/jpeg', 0.85));
    };
    img.onerror = () => { URL.revokeObjectURL(url); reject(new Error('Failed to load image')); };
    img.src = url;
  });
}

function captureFrame(video: HTMLVideoElement): string {
  const canvas = document.createElement('canvas');
  const maxSize = 1024;
  let { videoWidth: width, videoHeight: height } = video;
  if (width > maxSize || height > maxSize) {
    if (width > height) {
      height = Math.round(height * maxSize / width);
      width = maxSize;
    } else {
      width = Math.round(width * maxSize / height);
      height = maxSize;
    }
  }
  canvas.width = width;
  canvas.height = height;
  const ctx = canvas.getContext('2d');
  if (!ctx) return '';
  ctx.drawImage(video, 0, 0, width, height);
  return canvas.toDataURL('image/jpeg', 0.85);
}

export default function AIPhotoModal({ isOpen, onClose, onResult, enabledMacros: _enabledMacros, providerName }: Props) {
  const [mode, setMode] = useState<Mode>('camera');
  const [phase, setPhase] = useState<Phase>('capture');
  const [imageData, setImageData] = useState<string | null>(null);
  const [context, setContext] = useState('');
  const [errorMsg, setErrorMsg] = useState('');
  const videoRef = useRef<HTMLVideoElement>(null);
  const streamRef = useRef<MediaStream | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [cameraReady, setCameraReady] = useState(false);

  const stopCamera = useCallback(() => {
    if (streamRef.current) {
      streamRef.current.getTracks().forEach((t) => t.stop());
      streamRef.current = null;
    }
  }, []);

  const startCamera = useCallback(async () => {
    stopCamera();
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment', width: { ideal: 1024 }, height: { ideal: 768 } },
      });
      streamRef.current = stream;
      if (videoRef.current) {
        videoRef.current.srcObject = stream;
      }
    } catch {
      setErrorMsg('Could not access camera. Try uploading instead.');
      setMode('upload');
    }
  }, [stopCamera]);

  useEffect(() => {
    if (isOpen && mode === 'camera' && phase === 'capture' && !imageData) {
      startCamera();
    }
    return () => {
      if (mode === 'camera') stopCamera();
    };
  }, [isOpen, mode, phase, imageData, startCamera, stopCamera]);

  useEffect(() => {
    if (!isOpen) {
      stopCamera();
      setMode('camera');
      setPhase('capture');
      setImageData(null);
      setContext('');
      setErrorMsg('');
      setCameraReady(false);
    }
  }, [isOpen, stopCamera]);

  const handleCapture = () => {
    if (!videoRef.current) return;
    const data = captureFrame(videoRef.current);
    if (data) {
      setImageData(data);
      stopCamera();
    }
  };

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const data = await resizeImage(file);
      setImageData(data);
    } catch {
      setErrorMsg('Failed to process image.');
    }
  };

  const handleEstimate = async () => {
    if (!imageData) return;
    setPhase('loading');
    setErrorMsg('');
    try {
      const res = await estimateCalories({ image: imageData, context: context || undefined });
      if (res.ok && res.calories != null) {
        // Auto-fill the entry form and close
        onResult({
          calories: res.calories!,
          name: res.food || '',
          macros: res.macros,
        });
        return;
      } else {
        setErrorMsg(res.error || 'Estimation failed.');
        setPhase('error');
      }
    } catch {
      setErrorMsg('Estimation failed. Please try again.');
      setPhase('error');
    }
  };

  const handleRetry = () => {
    setPhase('capture');
    setImageData(null);
    setErrorMsg('');
    if (mode === 'camera') startCamera();
  };

  const handleModeSwitch = (newMode: Mode) => {
    if (newMode === mode) return;
    stopCamera();
    setMode(newMode);
    setImageData(null);
    setPhase('capture');
    setErrorMsg('');
  };

  return (
    <Dialog.Root open={isOpen} onOpenChange={(open) => { if (!open) onClose(); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/90 sm:bg-black/60 sm:backdrop-blur-sm" />
        <Dialog.Content className="fixed inset-0 z-50 bg-black flex flex-col overflow-hidden sm:overflow-y-auto sm:inset-auto sm:inset-x-4 sm:top-1/2 sm:-translate-y-1/2 sm:mx-auto sm:max-w-md sm:max-h-[90vh] sm:rounded-xl sm:border sm:border-border sm:bg-card">
          <div className="flex items-center justify-between px-4 py-2 border-b border-border bg-card/80 sm:bg-transparent shrink-0 z-10">
            <Dialog.Title className="text-sm font-semibold text-foreground">AI Calorie Estimate</Dialog.Title>
            <Dialog.Close className="size-8 flex items-center justify-center rounded-md border border-destructive/30 bg-destructive/10 text-destructive hover:bg-destructive/20 transition-colors cursor-pointer">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M18 6L6 18" /><path d="M6 6l12 12" />
              </svg>
            </Dialog.Close>
          </div>

          <div className="flex flex-col gap-3 flex-1 min-h-0 p-4 sm:flex-initial bg-card sm:bg-transparent">
            {/* Mode tabs */}
            {phase === 'capture' && !imageData && (
              <div className="flex gap-1 rounded-md bg-muted p-1">
                <button
                  type="button"
                  className={cn(
                    'flex-1 rounded-md px-3 py-1.5 text-xs font-medium transition-colors cursor-pointer',
                    mode === 'camera'
                      ? 'bg-card text-foreground shadow-sm'
                      : 'text-muted-foreground hover:text-foreground'
                  )}
                  onClick={() => handleModeSwitch('camera')}
                >
                  Camera
                </button>
                <button
                  type="button"
                  className={cn(
                    'flex-1 rounded-md px-3 py-1.5 text-xs font-medium transition-colors cursor-pointer',
                    mode === 'upload'
                      ? 'bg-card text-foreground shadow-sm'
                      : 'text-muted-foreground hover:text-foreground'
                  )}
                  onClick={() => handleModeSwitch('upload')}
                >
                  Upload
                </button>
              </div>
            )}

            {/* Preview area */}
            {phase === 'capture' && (
              <>
                <div className="relative rounded-md overflow-hidden bg-black/30 flex-1 sm:flex-initial min-h-[200px] flex items-center justify-center [&_video]:w-full [&_video]:h-full [&_video]:object-cover [&_video]:block [&_img]:w-full [&_img]:block [&_img]:rounded-md">
                  {mode === 'camera' && !imageData && (
                    <>
                      {!cameraReady && (
                        <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 z-10">
                          <div className="relative size-10">
                            <div className="absolute inset-0 rounded-full border-2 border-primary/20" />
                            <div className="absolute inset-0 rounded-full border-2 border-primary border-t-transparent animate-spin" />
                          </div>
                          <span className="text-xs text-muted-foreground">Starting camera...</span>
                        </div>
                      )}
                      <video ref={videoRef} autoPlay playsInline muted onPlaying={() => setCameraReady(true)} className={cameraReady ? '' : 'opacity-0'} />
                      <button
                        type="button"
                        className="absolute bottom-3 left-1/2 -translate-x-1/2 size-12 rounded-full border-4 border-white bg-white/20 hover:bg-white/40 cursor-pointer transition-colors"
                        onClick={handleCapture}
                        aria-label="Capture photo"
                      />
                    </>
                  )}
                  {mode === 'upload' && !imageData && (
                    <div className="flex flex-col items-center gap-3 py-8 text-muted-foreground">
                      <p className="text-sm">Select an image of your food</p>
                      <input
                        ref={fileInputRef}
                        type="file"
                        accept="image/*"
                        className="text-sm file:mr-2 file:rounded-md file:border-0 file:bg-primary file:px-3 file:py-1.5 file:text-xs file:font-medium file:text-white file:cursor-pointer"
                        onChange={handleFileChange}
                      />
                    </div>
                  )}
                  {imageData && (
                    <>
                      <img src={imageData} alt="Food preview" className="!object-contain !h-full" />
                      <div className="absolute bottom-0 left-0 right-0 flex flex-col gap-2 p-3 bg-gradient-to-t from-black/80 to-transparent pt-8">
                        <input
                          type="text"
                          className="rounded-md border border-input bg-black/50 px-3 py-2 text-sm text-foreground outline-none transition-colors focus:border-ring focus:ring-1 focus:ring-ring backdrop-blur-sm"
                          value={context}
                          onChange={(e) => setContext(e.target.value)}
                          placeholder="Describe the food (optional)"
                          maxLength={200}
                        />
                        <div className="flex gap-2">
                          <Button size="sm" onClick={handleEstimate}>Estimate</Button>
                          <Button size="sm" variant="ghost" onClick={handleRetry}>Retake</Button>
                        </div>
                      </div>
                    </>
                  )}
                </div>
              </>
            )}

            {/* Loading */}
            {phase === 'loading' && (
              <div className="flex flex-1 flex-col items-center justify-center gap-4 py-12">
                <div className="relative size-12">
                  <div className="absolute inset-0 rounded-full border-2 border-primary/20" />
                  <div className="absolute inset-0 rounded-full border-2 border-primary border-t-transparent animate-spin" />
                </div>
                <span className="text-sm font-medium text-muted-foreground animate-pulse">Analyzing food...</span>
              </div>
            )}

            {/* Error */}
            {phase === 'error' && (
              <>
                <div className="text-center text-sm text-destructive py-4">{errorMsg}</div>
                <div className="flex gap-2 justify-center">
                  <Button size="sm" onClick={handleRetry}>Retry</Button>
                  <Button size="sm" variant="ghost" onClick={onClose}>Close</Button>
                </div>
              </>
            )}

            {/* Inline error during capture */}
            {phase === 'capture' && errorMsg && (
              <div className="text-center text-sm text-destructive">{errorMsg}</div>
            )}

            {providerName && (
              <div className="text-center text-[10px] text-muted-foreground/60">
                Your photo will be sent to {providerName} for analysis
              </div>
            )}
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
