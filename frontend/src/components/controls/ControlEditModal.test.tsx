import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@/test/utils';
import ControlEditModal from './ControlEditModal';

describe('ControlEditModal', () => {
  const mockControl = {
    title: 'Access Control Policy',
    description: 'Ensure proper access controls are in place',
    guidance: 'Follow NIST guidelines',
    tags: ['security', 'access'],
  };

  const defaultProps = {
    control: mockControl,
    isOpen: true,
    onClose: vi.fn(),
    onSave: vi.fn(),
    isPending: false,
  };

  it('renders modal when open', () => {
    render(<ControlEditModal {...defaultProps} />);
    expect(screen.getByText('Edit Control')).toBeInTheDocument();
  });

  it('does not render when closed', () => {
    render(<ControlEditModal {...defaultProps} isOpen={false} />);
    expect(screen.queryByText('Edit Control')).not.toBeInTheDocument();
  });

  it('populates form with control data', () => {
    render(<ControlEditModal {...defaultProps} />);
    
    expect(screen.getByDisplayValue('Access Control Policy')).toBeInTheDocument();
    expect(screen.getByDisplayValue('Ensure proper access controls are in place')).toBeInTheDocument();
    expect(screen.getByDisplayValue('Follow NIST guidelines')).toBeInTheDocument();
    expect(screen.getByDisplayValue('security, access')).toBeInTheDocument();
  });

  it('calls onClose when X button is clicked', () => {
    render(<ControlEditModal {...defaultProps} />);
    
    // Click the X button (close button)
    const closeButton = screen.getByRole('button', { name: '' });
    fireEvent.click(closeButton);
    expect(defaultProps.onClose).toHaveBeenCalled();
  });

  it('calls onSave when form is submitted', () => {
    render(<ControlEditModal {...defaultProps} />);
    
    fireEvent.click(screen.getByText('Save Changes'));
    
    expect(defaultProps.onSave).toHaveBeenCalledWith({
      title: 'Access Control Policy',
      description: 'Ensure proper access controls are in place',
      guidance: 'Follow NIST guidelines',
      tags: ['security', 'access'],
    });
  });

  it('shows form fields with labels', () => {
    render(<ControlEditModal {...defaultProps} />);
    
    expect(screen.getByText('Title')).toBeInTheDocument();
    expect(screen.getByText('Description')).toBeInTheDocument();
    expect(screen.getByText(/Implementation Guidance/)).toBeInTheDocument();
    expect(screen.getByText(/Tags/)).toBeInTheDocument();
  });
});
