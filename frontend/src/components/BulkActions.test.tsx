import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, act } from '@/test/utils';
import { useSelection, SelectCheckbox } from './BulkActions';
import { renderHook } from '@testing-library/react';

describe('useSelection Hook', () => {
  const mockItems = [
    { id: '1', name: 'Item 1' },
    { id: '2', name: 'Item 2' },
    { id: '3', name: 'Item 3' },
  ];

  it('starts with no selection', () => {
    const { result } = renderHook(() => useSelection(mockItems));
    
    expect(result.current.count).toBe(0);
    expect(result.current.isAllSelected).toBe(false);
  });

  it('can toggle selection', () => {
    const { result } = renderHook(() => useSelection(mockItems));
    
    act(() => {
      result.current.toggle('1');
    });
    
    expect(result.current.count).toBe(1);
    expect(result.current.isSelected('1')).toBe(true);
  });

  it('can select all', () => {
    const { result } = renderHook(() => useSelection(mockItems));
    
    act(() => {
      result.current.selectAll();
    });
    
    expect(result.current.count).toBe(3);
    expect(result.current.isAllSelected).toBe(true);
  });

  it('can clear selection', () => {
    const { result } = renderHook(() => useSelection(mockItems));
    
    act(() => {
      result.current.selectAll();
      result.current.clearSelection();
    });
    
    expect(result.current.count).toBe(0);
  });

  it('returns selected items', () => {
    const { result } = renderHook(() => useSelection(mockItems));
    
    act(() => {
      result.current.toggle('1');
      result.current.toggle('2');
    });
    
    expect(result.current.selectedItems.length).toBe(2);
    expect(result.current.selectedItems.map(i => i.id)).toContain('1');
    expect(result.current.selectedItems.map(i => i.id)).toContain('2');
  });
});

describe('SelectCheckbox', () => {
  it('renders unchecked state', () => {
    render(<SelectCheckbox checked={false} onChange={vi.fn()} />);
    
    const checkbox = screen.getByRole('checkbox');
    expect(checkbox).not.toBeChecked();
  });

  it('renders checked state', () => {
    render(<SelectCheckbox checked={true} onChange={vi.fn()} />);
    
    const checkbox = screen.getByRole('checkbox');
    expect(checkbox).toBeChecked();
  });

  it('calls onChange when clicked', () => {
    const handleChange = vi.fn();
    render(<SelectCheckbox checked={false} onChange={handleChange} />);
    
    fireEvent.click(screen.getByRole('checkbox'));
    expect(handleChange).toHaveBeenCalled();
  });

  it('can be disabled', () => {
    render(<SelectCheckbox checked={false} onChange={vi.fn()} disabled />);
    
    expect(screen.getByRole('checkbox')).toBeDisabled();
  });
});
