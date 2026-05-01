import { create } from 'zustand';

export interface StepUpRequest {
  methods: string[];
  totpRequired: boolean;
  // Resolves with the original API call's result once step-up succeeds and the
  // request is retried. The modal awaits this; callers of api() see a normal
  // resolution (or rejection on cancel).
  retry: () => Promise<void>;
  cancel: () => void;
}

interface StepUpState {
  pending: StepUpRequest | null;
  enqueue: (req: StepUpRequest) => void;
  clear: () => void;
}

export const useStepUpStore = create<StepUpState>((set) => ({
  pending: null,
  enqueue: (req) => set({ pending: req }),
  clear: () => set({ pending: null }),
}));
