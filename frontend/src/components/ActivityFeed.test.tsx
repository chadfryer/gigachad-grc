import { describe, it, expect, vi } from 'vitest';
import { render, screen } from '@/test/utils';
import { ActivityFeed } from './ActivityFeed';

// Mock react-query
vi.mock('@tanstack/react-query', async () => {
  const actual = await vi.importActual('@tanstack/react-query');
  return {
    ...actual,
    useQuery: vi.fn().mockReturnValue({
      data: {
        logs: [
          {
            id: '1',
            action: 'created',
            entityType: 'control',
            entityId: 'ctrl-1',
            entityName: 'Test Control',
            userName: 'John Doe',
            createdAt: new Date().toISOString(),
          },
          {
            id: '2',
            action: 'updated',
            entityType: 'risk',
            entityId: 'risk-1',
            entityName: 'Test Risk',
            userName: 'Jane Smith',
            createdAt: new Date().toISOString(),
          },
        ],
        total: 2,
      },
      isLoading: false,
    }),
  };
});

describe('ActivityFeed', () => {
  it('renders activity feed header', () => {
    render(<ActivityFeed />);
    expect(screen.getByText(/recent activity/i)).toBeInTheDocument();
  });

  it('displays activity items', () => {
    render(<ActivityFeed />);
    
    expect(screen.getByText(/Test Control/i)).toBeInTheDocument();
    expect(screen.getByText(/Test Risk/i)).toBeInTheDocument();
  });

  it('shows user names for activities', () => {
    render(<ActivityFeed />);
    
    expect(screen.getByText(/John Doe/i)).toBeInTheDocument();
    expect(screen.getByText(/Jane Smith/i)).toBeInTheDocument();
  });

  it('renders action icons', () => {
    render(<ActivityFeed />);
    
    // Should have SVG icons for the actions
    const icons = document.querySelectorAll('svg');
    expect(icons.length).toBeGreaterThan(0);
  });
});
