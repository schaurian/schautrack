import { api } from './client';

export interface BarcodeResult {
  ok: boolean;
  name?: string;
  caloriesPer100g?: number | null;
  macrosPer100g?: Record<string, number>;
  servingSize?: string | null;
  servingQuantity?: number | null;
  note?: string;
  error?: string;
}

export function lookupBarcode(code: string) {
  return api<BarcodeResult>(`/api/barcode/${code}`);
}
