import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@/test/utils';
import { ComplianceScoreCard } from './ComplianceScoreCard';

describe('ComplianceScoreCard', () => {
  const defaultProps = {
    score: 85,
    implementedControls: 85,
    totalControls: 100,
  };

  it('displays score correctly', () => {
    render(<ComplianceScoreCard {...defaultProps} />);
    expect(screen.getByText('85%')).toBeInTheDocument();
  });

  it('displays framework name when provided', () => {
    render(<ComplianceScoreCard {...defaultProps} frameworkName="SOC 2" />);
    expect(screen.getByText('SOC 2')).toBeInTheDocument();
  });

  it('shows default title when no framework name', () => {
    render(<ComplianceScoreCard {...defaultProps} />);
    expect(screen.getByText('Overall Compliance')).toBeInTheDocument();
  });

  it('shows positive trend with correct styling', () => {
    render(<ComplianceScoreCard {...defaultProps} previousScore={80} />);
    const trendElement = screen.getByText('5%');
    expect(trendElement).toBeInTheDocument();
    expect(trendElement).toHaveClass('text-green-500');
  });

  it('shows negative trend with correct styling', () => {
    render(<ComplianceScoreCard {...defaultProps} previousScore={90} />);
    const trendElement = screen.getByText('5%');
    expect(trendElement).toBeInTheDocument();
    expect(trendElement).toHaveClass('text-red-500');
  });

  it('displays implemented and remaining counts', () => {
    render(<ComplianceScoreCard {...defaultProps} />);
    // Should show "85 of 100 controls implemented" and "15 remaining"
    expect(screen.getByText(/controls implemented/i)).toBeInTheDocument();
    expect(screen.getByText(/remaining/i)).toBeInTheDocument();
  });

  it('calls onClick when clicked', () => {
    const handleClick = vi.fn();
    render(<ComplianceScoreCard {...defaultProps} onClick={handleClick} />);
    
    fireEvent.click(screen.getByText('85%'));
    expect(handleClick).toHaveBeenCalled();
  });

  it('handles 100% score', () => {
    render(<ComplianceScoreCard {...defaultProps} score={100} />);
    expect(screen.getByText('100%')).toBeInTheDocument();
  });

  it('handles 0% score', () => {
    render(<ComplianceScoreCard {...defaultProps} score={0} />);
    expect(screen.getByText('0%')).toBeInTheDocument();
  });
});
