import { useState, useRef, useCallback, useEffect, useMemo } from 'react';
import * as Dialog from '@radix-ui/react-dialog';
import Quagga from '@ericblade/quagga2';
import { lookupBarcode } from '@/api/barcode';
import { MACRO_LABELS } from '@/lib/macros';
import { Button } from '@/components/ui/Button';
import { cn } from '@/lib/utils';

interface Props {
  isOpen: boolean;
  onClose: () => void;
  onResult: (result: { calories: number; name: string; macros?: Record<string, number> }) => void;
  enabledMacros: string[];
}

type Phase = 'scanning' | 'loading' | 'result' | 'error';
type Mode = 'camera' | 'upload' | 'manual';

interface ProductData {
  name?: string;
  caloriesPer100g: number;
  macrosPer100g: Record<string, number>;
  servingSize?: string | null;
  servingQuantity?: number | null;
}

export default function BarcodeScanModal({ isOpen, onClose, onResult, enabledMacros }: Props) {
  const [phase, setPhase] = useState<Phase>('scanning');
  const [mode, setMode] = useState<Mode>('camera');
  const [barcode, setBarcode] = useState('');
  const [manualCode, setManualCode] = useState('');
  const [product, setProduct] = useState<ProductData | null>(null);
  const [grams, setGrams] = useState('100');
  const [errorMsg, setErrorMsg] = useState('');
  const [cameraAvailable, setCameraAvailable] = useState(true);
  const [scannerReady, setScannerReady] = useState(false);
  const scannerRef = useRef<HTMLDivElement>(null);
  const quaggaRunning = useRef(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const stopScanner = useCallback(() => {
    if (quaggaRunning.current) {
      Quagga.stop();
      quaggaRunning.current = false;
    }
  }, []);

  const doLookup = useCallback(async (code: string) => {
    setBarcode(code);
    setPhase('loading');
    setErrorMsg('');
    stopScanner();

    try {
      const res = await lookupBarcode(code);
      if (!res.ok) {
        setErrorMsg(res.error || 'Product not found.');
        setPhase('error');
        return;
      }
      if (res.caloriesPer100g == null) {
        setErrorMsg(res.note || 'No calorie data available.');
        setProduct(null);
        setPhase('error');
        return;
      }
      const p: ProductData = {
        name: res.name,
        caloriesPer100g: res.caloriesPer100g,
        macrosPer100g: res.macrosPer100g || {},
        servingSize: res.servingSize,
        servingQuantity: res.servingQuantity,
      };
      setProduct(p);
      setGrams(String(p.servingQuantity || 100));
      setPhase('result');
    } catch {
      setErrorMsg('Lookup failed. Please try again.');
      setPhase('error');
    }
  }, [stopScanner]);

  const startScanner = useCallback(() => {
    if (!scannerRef.current || quaggaRunning.current) return;

    Quagga.init(
      {
        inputStream: {
          type: 'LiveStream',
          target: scannerRef.current,
          constraints: {
            facingMode: 'environment',
            width: { ideal: 640 },
            height: { ideal: 480 },
          },
        },
        decoder: {
          readers: ['ean_reader', 'ean_8_reader', 'upc_reader', 'upc_e_reader'],
        },
        locate: true,
      },
      (err: Error | null) => {
        if (err) {
          setCameraAvailable(false);
          return;
        }
        Quagga.start();
        quaggaRunning.current = true;
        setScannerReady(true);
      }
    );

    Quagga.onDetected((data) => {
      const code = data.codeResult?.code;
      if (code && /^\d{8,13}$/.test(code)) {
        doLookup(code);
      }
    });
  }, [doLookup]);

  useEffect(() => {
    if (isOpen && phase === 'scanning' && mode === 'camera' && cameraAvailable) {
      const timer = setTimeout(startScanner, 100);
      return () => clearTimeout(timer);
    }
    return undefined;
  }, [isOpen, phase, mode, cameraAvailable, startScanner]);

  useEffect(() => {
    if (!isOpen) {
      stopScanner();
      setPhase('scanning');
      setMode('camera');
      setBarcode('');
      setManualCode('');
      setProduct(null);
      setGrams('100');
      setErrorMsg('');
      setCameraAvailable(true);
      setScannerReady(false);
    }
  }, [isOpen, stopScanner]);

  const handleFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setErrorMsg('');

    const src = URL.createObjectURL(file);

    Quagga.decodeSingle(
      {
        src,
        numOfWorkers: 0,
        decoder: {
          readers: ['ean_reader', 'ean_8_reader', 'upc_reader', 'upc_e_reader'],
        },
        locate: true,
      },
      (result) => {
        URL.revokeObjectURL(src);
        const code = result?.codeResult?.code;
        if (code && /^\d{8,13}$/.test(code)) {
          doLookup(code);
        } else {
          setErrorMsg('No barcode found in image. Try a clearer photo.');
        }
      }
    );

    // Reset file input so same file can be re-selected
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  const handleManualSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    const code = manualCode.trim();
    if (/^\d{8,13}$/.test(code)) {
      doLookup(code);
    } else {
      setErrorMsg('Enter a valid barcode (8-13 digits).');
    }
  };

  const handleModeSwitch = (newMode: Mode) => {
    if (newMode === mode) return;
    stopScanner();
    setMode(newMode);
    setErrorMsg('');
  };

  const scaled = useMemo(() => {
    if (!product) return null;
    const g = parseFloat(grams) || 0;
    const factor = g / 100;
    const calories = Math.round(product.caloriesPer100g * factor);
    const macros: Record<string, number> = {};
    for (const [key, val] of Object.entries(product.macrosPer100g)) {
      macros[key] = Math.round(val * factor);
    }
    return { calories, macros };
  }, [product, grams]);

  const handleAddEntry = () => {
    if (!scaled || !product) return;
    onResult({
      calories: scaled.calories,
      name: product.name || '',
      macros: scaled.macros,
    });
  };

  const handleRetry = () => {
    setPhase('scanning');
    setBarcode('');
    setManualCode('');
    setProduct(null);
    setGrams('100');
    setErrorMsg('');
  };

  const handleServingPreset = (g: number) => {
    setGrams(String(g));
  };

  return (
    <Dialog.Root open={isOpen} onOpenChange={(open) => { if (!open) onClose(); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 z-50 bg-black/90 sm:bg-black/60 sm:backdrop-blur-sm" />
        <Dialog.Content className="fixed inset-0 z-50 bg-card flex flex-col overflow-y-auto sm:inset-auto sm:inset-x-4 sm:top-1/2 sm:-translate-y-1/2 sm:mx-auto sm:max-w-md sm:max-h-[90vh] sm:rounded-xl sm:border sm:border-border">
          <div className="flex items-center justify-between px-4 py-3 border-b border-border">
            <Dialog.Title className="text-sm font-semibold text-foreground">Scan Barcode</Dialog.Title>
            <Dialog.Close className="bg-transparent border-0 p-0 text-xl text-muted-foreground hover:text-foreground cursor-pointer leading-none">
              &times;
            </Dialog.Close>
          </div>

          <div className="p-4 flex flex-col gap-3">
            {/* Mode tabs */}
            {phase === 'scanning' && (
              <div className="flex gap-1 rounded-md bg-muted p-1">
                {(['camera', 'upload', 'manual'] as const).map((m) => (
                  <button
                    key={m}
                    type="button"
                    className={cn(
                      'flex-1 rounded-md px-3 py-1.5 text-xs font-medium transition-colors cursor-pointer',
                      mode === m
                        ? 'bg-card text-foreground shadow-sm'
                        : 'text-muted-foreground hover:text-foreground'
                    )}
                    onClick={() => handleModeSwitch(m)}
                  >
                    {m === 'camera' ? 'Camera' : m === 'upload' ? 'Upload' : 'Manual'}
                  </button>
                ))}
              </div>
            )}

            {/* Scanning phase */}
            {phase === 'scanning' && (
              <>
                {mode === 'camera' && (
                  cameraAvailable ? (
                    <div
                      ref={scannerRef}
                      className="relative rounded-md overflow-hidden bg-black/30 min-h-[240px] [&_video]:w-full [&_video]:block [&_canvas]:hidden"
                    >
                      {!scannerReady && (
                        <div className="absolute inset-0 flex flex-col items-center justify-center gap-3 z-10">
                          <div className="relative size-10">
                            <div className="absolute inset-0 rounded-full border-2 border-primary/20" />
                            <div className="absolute inset-0 rounded-full border-2 border-primary border-t-transparent animate-spin" />
                          </div>
                          <span className="text-xs text-muted-foreground">Starting camera...</span>
                        </div>
                      )}
                      {scannerReady && <div className="absolute inset-x-8 top-1/2 -translate-y-1/2 h-0.5 bg-primary/60 z-10 pointer-events-none" />}
                    </div>
                  ) : (
                    <div className="flex flex-col items-center gap-2 py-6 text-muted-foreground">
                      <p className="text-sm">Camera not available.</p>
                    </div>
                  )
                )}

                {mode === 'upload' && (
                  <div className="flex flex-col items-center gap-3 py-8 text-muted-foreground">
                    <p className="text-sm">Upload a photo of a barcode</p>
                    <input
                      ref={fileInputRef}
                      type="file"
                      accept="image/*"
                      className="text-sm file:mr-2 file:rounded-md file:border-0 file:bg-primary file:px-3 file:py-1.5 file:text-xs file:font-medium file:text-white file:cursor-pointer"
                      onChange={handleFileChange}
                    />
                  </div>
                )}

                {mode === 'manual' && (
                  <form onSubmit={handleManualSubmit} className="flex gap-2 py-4">
                    <input
                      type="text"
                      className="flex-1 rounded-md border border-input bg-muted/50 px-3 py-2 text-sm text-foreground outline-none transition-colors focus:border-ring focus:ring-1 focus:ring-ring placeholder:text-muted-foreground/50"
                      value={manualCode}
                      onChange={(e) => { setManualCode(e.target.value); setErrorMsg(''); }}
                      placeholder="Enter barcode number"
                      inputMode="numeric"
                      maxLength={13}
                      autoFocus
                    />
                    <Button type="submit" size="sm">Look up</Button>
                  </form>
                )}

                {errorMsg && (
                  <div className="text-center text-sm text-destructive">{errorMsg}</div>
                )}
              </>
            )}

            {/* Loading phase */}
            {phase === 'loading' && (
              <div className="flex flex-1 flex-col items-center justify-center gap-4 py-12">
                <div className="relative size-12">
                  <div className="absolute inset-0 rounded-full border-2 border-primary/20" />
                  <div className="absolute inset-0 rounded-full border-2 border-primary border-t-transparent animate-spin" />
                </div>
                <span className="text-sm font-medium text-muted-foreground animate-pulse">Looking up {barcode}...</span>
              </div>
            )}

            {/* Result phase */}
            {phase === 'result' && product && scaled && (
              <>
                <div className="flex flex-col items-center gap-1 py-2">
                  {product.name && (
                    <div className="text-base font-semibold text-foreground text-center">{product.name}</div>
                  )}
                  <div className="text-xs text-muted-foreground">
                    {product.caloriesPer100g} cal per 100g
                    {product.servingSize && ` · serving: ${product.servingSize}`}
                  </div>
                </div>

                {/* Amount selector */}
                <div className="flex items-center gap-2">
                  <div className="relative flex-1">
                    <input
                      type="text"
                      inputMode="numeric"
                      className="w-full rounded-md border border-input bg-muted/50 px-3 py-2 pr-8 text-sm text-foreground outline-none transition-colors focus:border-ring focus:ring-1 focus:ring-ring"
                      value={grams}
                      onChange={(e) => setGrams(e.target.value)}
                    />
                    <span className="absolute right-2.5 top-1/2 -translate-y-1/2 text-[10px] text-muted-foreground pointer-events-none">g</span>
                  </div>
                  <div className="flex gap-1">
                    {product.servingQuantity && product.servingQuantity !== 100 && (
                      <button
                        type="button"
                        className={`rounded-md px-2.5 py-2 text-xs font-medium transition-colors cursor-pointer border ${parseFloat(grams) === product.servingQuantity ? 'border-primary bg-primary/10 text-primary' : 'border-border bg-transparent text-muted-foreground hover:text-foreground hover:border-primary/50'}`}
                        onClick={() => handleServingPreset(product.servingQuantity!)}
                      >
                        {product.servingSize || `${product.servingQuantity}g`}
                      </button>
                    )}
                    <button
                      type="button"
                      className={`rounded-md px-2.5 py-2 text-xs font-medium transition-colors cursor-pointer border ${parseFloat(grams) === 100 ? 'border-primary bg-primary/10 text-primary' : 'border-border bg-transparent text-muted-foreground hover:text-foreground hover:border-primary/50'}`}
                      onClick={() => handleServingPreset(100)}
                    >
                      100g
                    </button>
                  </div>
                </div>

                {/* Computed values */}
                <div className="flex flex-col items-center gap-1">
                  <div className="text-2xl font-bold text-primary tabular-nums">{scaled.calories} cal</div>
                  {Object.keys(scaled.macros).length > 0 && (
                    <div className="flex gap-4 mt-1">
                      {enabledMacros.map((key) => {
                        const val = scaled.macros[key];
                        if (val == null) return null;
                        const label = MACRO_LABELS[key as keyof typeof MACRO_LABELS];
                        return (
                          <div key={key} className="flex flex-col items-center">
                            <span className="text-sm font-semibold tabular-nums">{val}g</span>
                            <span className="text-xs uppercase tracking-wider text-muted-foreground">{label?.short || key}</span>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>

                <div className="flex gap-2 justify-center">
                  <Button size="sm" onClick={handleAddEntry}>Add Entry</Button>
                  <Button size="sm" variant="ghost" onClick={handleRetry}>Scan Another</Button>
                </div>
              </>
            )}

            {/* Attribution */}
            {(phase === 'result' || phase === 'scanning') && (
              <div className="text-center text-[10px] text-muted-foreground/60">
                Barcode data is sent to and provided by{' '}
                <a href="https://world.openfoodfacts.org" target="_blank" rel="noopener noreferrer" className="underline hover:text-muted-foreground">
                  Open Food Facts
                </a>
                {' '}&middot; ODbL
              </div>
            )}

            {/* Error phase */}
            {phase === 'error' && (
              <>
                <div className="text-center py-4">
                  <div className="text-sm text-destructive">{errorMsg}</div>
                </div>
                <div className="flex gap-2 justify-center">
                  <Button size="sm" onClick={handleRetry}>Try Again</Button>
                  <Button size="sm" variant="ghost" onClick={onClose}>Close</Button>
                </div>
              </>
            )}
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
