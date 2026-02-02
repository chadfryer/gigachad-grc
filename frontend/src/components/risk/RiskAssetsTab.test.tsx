import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@/test/utils';
import RiskAssetsTab from './RiskAssetsTab';

describe('RiskAssetsTab', () => {
  const mockAssets = [
    {
      id: 'asset-1',
      assetId: 'AST-001',
      name: 'Production Database',
      type: 'database',
      criticality: 'critical',
    },
    {
      id: 'asset-2',
      assetId: 'AST-002',
      name: 'Web Server',
      type: 'server',
      criticality: 'high',
    },
  ];

  const defaultProps = {
    assets: mockAssets,
    onLinkAsset: vi.fn(),
    onUnlinkAsset: vi.fn(),
    isUnlinking: false,
  };

  it('renders section header', () => {
    render(<RiskAssetsTab {...defaultProps} />);
    expect(screen.getByText('Affected Assets')).toBeInTheDocument();
  });

  it('renders link asset button', () => {
    render(<RiskAssetsTab {...defaultProps} />);
    expect(screen.getByText('Link Asset')).toBeInTheDocument();
  });

  it('displays asset list', () => {
    render(<RiskAssetsTab {...defaultProps} />);
    
    expect(screen.getByText('Production Database')).toBeInTheDocument();
    expect(screen.getByText('Web Server')).toBeInTheDocument();
  });

  it('displays asset IDs', () => {
    render(<RiskAssetsTab {...defaultProps} />);
    
    expect(screen.getByText('AST-001')).toBeInTheDocument();
    expect(screen.getByText('AST-002')).toBeInTheDocument();
  });

  it('displays criticality badges', () => {
    render(<RiskAssetsTab {...defaultProps} />);
    
    expect(screen.getByText('critical')).toBeInTheDocument();
    expect(screen.getByText('high')).toBeInTheDocument();
  });

  it('calls onLinkAsset when link button is clicked', () => {
    render(<RiskAssetsTab {...defaultProps} />);
    
    fireEvent.click(screen.getByText('Link Asset'));
    expect(defaultProps.onLinkAsset).toHaveBeenCalled();
  });

  it('shows empty state when no assets', () => {
    render(<RiskAssetsTab {...defaultProps} assets={[]} />);
    
    expect(screen.getByText('No assets linked to this risk')).toBeInTheDocument();
  });
});
