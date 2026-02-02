import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@/test/utils';
import CommentsPanel from './CommentsPanel';

// Mock react-query
vi.mock('@tanstack/react-query', async () => {
  const actual = await vi.importActual('@tanstack/react-query');
  return {
    ...actual,
    useQuery: vi.fn().mockReturnValue({
      data: [
        {
          id: '1',
          content: 'First comment',
          userName: 'John Doe',
          userEmail: 'john@test.com',
          createdAt: new Date().toISOString(),
          isResolved: false,
        },
        {
          id: '2',
          content: 'Second comment',
          userName: 'Jane Smith',
          userEmail: 'jane@test.com',
          createdAt: new Date().toISOString(),
          isResolved: false,
        },
      ],
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

// Mock auth context
vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    user: { id: 'user-1', email: 'test@test.com' },
  }),
}));

describe('CommentsPanel', () => {
  const defaultProps = {
    entityType: 'control',
    entityId: 'ctrl-123',
  };

  it('renders comments panel header', () => {
    render(<CommentsPanel {...defaultProps} />);
    expect(screen.getByText(/comments/i)).toBeInTheDocument();
  });

  it('displays comment count', () => {
    render(<CommentsPanel {...defaultProps} />);
    expect(screen.getByText(/\(2\)/)).toBeInTheDocument();
  });

  it('displays existing comments', () => {
    render(<CommentsPanel {...defaultProps} />);
    
    expect(screen.getByText('First comment')).toBeInTheDocument();
    expect(screen.getByText('Second comment')).toBeInTheDocument();
  });

  it('has an input for new comments', () => {
    render(<CommentsPanel {...defaultProps} />);
    
    const input = screen.getByPlaceholderText(/add a comment/i);
    expect(input).toBeInTheDocument();
  });

  it('can type in the comment input', () => {
    render(<CommentsPanel {...defaultProps} />);
    
    const input = screen.getByPlaceholderText(/add a comment/i);
    fireEvent.change(input, { target: { value: 'My new comment' } });
    
    expect(input).toHaveValue('My new comment');
  });
});
