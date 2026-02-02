import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@/test/utils';
import RiskControlsTab from './RiskControlsTab';

describe('RiskControlsTab', () => {
  const mockControls = [
    {
      id: 'ctrl-1',
      controlId: 'CTRL-001',
      title: 'Access Control Policy',
      status: 'implemented',
      effectiveness: 'full',
    },
    {
      id: 'ctrl-2',
      controlId: 'CTRL-002',
      title: 'Password Requirements',
      status: 'in_progress',
      effectiveness: 'partial',
    },
  ];

  const defaultProps = {
    controls: mockControls,
    onLinkControl: vi.fn(),
    onUnlinkControl: vi.fn(),
    onUpdateEffectiveness: vi.fn(),
    isUnlinking: false,
  };

  it('renders section header', () => {
    render(<RiskControlsTab {...defaultProps} />);
    expect(screen.getByText('Mitigating Controls')).toBeInTheDocument();
  });

  it('renders link control button', () => {
    render(<RiskControlsTab {...defaultProps} />);
    expect(screen.getByText('Link Control')).toBeInTheDocument();
  });

  it('displays control list', () => {
    render(<RiskControlsTab {...defaultProps} />);
    
    expect(screen.getByText('Access Control Policy')).toBeInTheDocument();
    expect(screen.getByText('Password Requirements')).toBeInTheDocument();
  });

  it('displays control IDs', () => {
    render(<RiskControlsTab {...defaultProps} />);
    
    expect(screen.getByText('CTRL-001')).toBeInTheDocument();
    expect(screen.getByText('CTRL-002')).toBeInTheDocument();
  });

  it('calls onLinkControl when link button is clicked', () => {
    render(<RiskControlsTab {...defaultProps} />);
    
    fireEvent.click(screen.getByText('Link Control'));
    expect(defaultProps.onLinkControl).toHaveBeenCalled();
  });

  it('shows empty state when no controls', () => {
    render(<RiskControlsTab {...defaultProps} controls={[]} />);
    
    expect(screen.getByText('No controls linked to this risk')).toBeInTheDocument();
  });
});
