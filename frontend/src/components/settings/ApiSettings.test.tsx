import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@/test/utils';
import ApiSettings from './ApiSettings';

// Mock react-query
vi.mock('@tanstack/react-query', async () => {
  const actual = await vi.importActual('@tanstack/react-query');
  return {
    ...actual,
    useQuery: vi.fn().mockReturnValue({
      data: {
        keys: [
          {
            id: 'key-1',
            name: 'Production API Key',
            keyPrefix: 'abc123',
            isActive: true,
            scopes: ['all'],
            createdAt: new Date().toISOString(),
            lastUsedAt: new Date().toISOString(),
          },
          {
            id: 'key-2',
            name: 'Test API Key',
            keyPrefix: 'xyz789',
            isActive: false,
            scopes: ['controls:read'],
            createdAt: new Date().toISOString(),
          },
        ],
      },
      isLoading: false,
    }),
    useMutation: vi.fn().mockReturnValue({
      mutate: vi.fn(),
      isPending: false,
    }),
    useQueryClient: vi.fn().mockReturnValue({
      invalidateQueries: vi.fn(),
    }),
  };
});

describe('ApiSettings', () => {
  it('renders API keys header', () => {
    render(<ApiSettings />);
    expect(screen.getByText('API Keys')).toBeInTheDocument();
  });

  it('displays existing API keys', () => {
    render(<ApiSettings />);
    
    expect(screen.getByText('Production API Key')).toBeInTheDocument();
    expect(screen.getByText('Test API Key')).toBeInTheDocument();
  });

  it('renders Generate New Key button', () => {
    render(<ApiSettings />);
    
    expect(screen.getByText('Generate New Key')).toBeInTheDocument();
  });

  it('opens create modal when Generate New Key is clicked', () => {
    render(<ApiSettings />);
    
    fireEvent.click(screen.getByText('Generate New Key'));
    
    expect(screen.getByText('Create API Key')).toBeInTheDocument();
  });

  it('shows description text', () => {
    render(<ApiSettings />);
    
    expect(screen.getByText(/Manage API keys for programmatic access/)).toBeInTheDocument();
  });
});
