import { describe, it, expect } from 'vitest';
import { render, screen } from '@/test/utils';
import { QuickActions } from './QuickActions';

describe('QuickActions', () => {
  it('renders quick action buttons', () => {
    render(<QuickActions />);
    
    // Check for common quick action labels
    expect(screen.getByText('New Control')).toBeInTheDocument();
    expect(screen.getByText('New Risk')).toBeInTheDocument();
  });

  it('renders quick actions header', () => {
    render(<QuickActions />);
    
    expect(screen.getByText('Quick Actions')).toBeInTheDocument();
  });

  it('renders upload evidence action', () => {
    render(<QuickActions />);
    
    expect(screen.getByText('Upload Evidence')).toBeInTheDocument();
  });

  it('applies custom className', () => {
    const { container } = render(<QuickActions className="custom-class" />);
    expect(container.firstChild).toHaveClass('custom-class');
  });
});
