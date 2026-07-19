import { Component, type ReactNode } from 'react';
import { Button } from '@/components/ui/Button';
import i18n from '@/i18n';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export default class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error) {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error('React Error Boundary caught:', error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex min-h-screen items-center justify-center bg-background text-foreground p-8">
          <div className="text-center max-w-md">
            <h1 className="text-xl font-semibold mb-2">{i18n.t('errorBoundary.title', { ns: 'common' })}</h1>
            <p className="text-sm text-muted-foreground mb-4">
              {this.state.error?.message || i18n.t('errorBoundary.unexpectedError', { ns: 'common' })}
            </p>
            <Button onClick={() => window.location.reload()}>{i18n.t('errorBoundary.reload', { ns: 'common' })}</Button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
