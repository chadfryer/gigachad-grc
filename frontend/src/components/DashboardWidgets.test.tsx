import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@/test/utils';
import { DashboardWidgets } from './DashboardWidgets';

describe('DashboardWidgets', () => {
  const mockWidgets = [
    {
      id: 'widget-1',
      title: 'Controls Overview',
      component: <div data-testid="widget-content-1">Controls Content</div>,
      defaultVisible: true,
    },
    {
      id: 'widget-2',
      title: 'Risk Summary',
      component: <div data-testid="widget-content-2">Risks Content</div>,
      defaultVisible: true,
    },
  ];

  const defaultProps = {
    widgets: mockWidgets,
    storageKey: 'test-dashboard',
  };

  // Mock localStorage
  beforeEach(() => {
    vi.spyOn(Storage.prototype, 'getItem').mockReturnValue(null);
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('renders widget content', () => {
    render(<DashboardWidgets {...defaultProps} />);
    
    expect(screen.getByTestId('widget-content-1')).toBeInTheDocument();
    expect(screen.getByTestId('widget-content-2')).toBeInTheDocument();
  });

  it('renders widgets container', () => {
    const { container } = render(<DashboardWidgets {...defaultProps} />);
    expect(container.firstChild).toBeInTheDocument();
  });

  it('applies custom className', () => {
    const { container } = render(
      <DashboardWidgets {...defaultProps} className="custom-class" />
    );
    expect(container.firstChild).toHaveClass('custom-class');
  });

  it('has customize button', () => {
    render(<DashboardWidgets {...defaultProps} />);
    expect(screen.getByText('Customize')).toBeInTheDocument();
  });

  it('toggles customization mode when clicked', () => {
    render(<DashboardWidgets {...defaultProps} />);
    
    fireEvent.click(screen.getByText('Customize'));
    
    // Should show Done button when customizing
    expect(screen.getByText('Done')).toBeInTheDocument();
  });
});
