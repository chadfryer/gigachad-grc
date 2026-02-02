import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen } from '@/test/utils';
import ErrorBoundary from './ErrorBoundary';

describe('ErrorBoundary', () => {
  // Suppress console.error for these tests
  const originalError = console.error;
  
  beforeEach(() => {
    console.error = vi.fn();
  });

  afterEach(() => {
    console.error = originalError;
  });

  it('renders children when there is no error', () => {
    render(
      <ErrorBoundary>
        <div>Child content</div>
      </ErrorBoundary>
    );
    expect(screen.getByText('Child content')).toBeInTheDocument();
  });

  it('does not render fallback when children render successfully', () => {
    render(
      <ErrorBoundary fallback={<div>Fallback</div>}>
        <div>Success</div>
      </ErrorBoundary>
    );
    
    expect(screen.getByText('Success')).toBeInTheDocument();
    expect(screen.queryByText('Fallback')).not.toBeInTheDocument();
  });

  it('renders nested children correctly', () => {
    render(
      <ErrorBoundary>
        <div>
          <span>Nested content</span>
          <p>More content</p>
        </div>
      </ErrorBoundary>
    );
    
    expect(screen.getByText('Nested content')).toBeInTheDocument();
    expect(screen.getByText('More content')).toBeInTheDocument();
  });
});
