import { describe, it, expect } from 'vitest';
import { render, screen, fireEvent } from '@/test/utils';
import { Tooltip } from './Tooltip';

describe('Tooltip', () => {
  it('renders children correctly', () => {
    render(
      <Tooltip content="Tooltip text">
        <button>Hover me</button>
      </Tooltip>
    );
    expect(screen.getByRole('button')).toHaveTextContent('Hover me');
  });

  it('shows tooltip on hover', () => {
    render(
      <Tooltip content="Tooltip text">
        <button>Hover me</button>
      </Tooltip>
    );
    
    const trigger = screen.getByRole('button');
    fireEvent.mouseEnter(trigger.parentElement!);
    
    expect(screen.getByText('Tooltip text')).toBeInTheDocument();
  });

  it('hides tooltip on mouse leave', () => {
    render(
      <Tooltip content="Tooltip text">
        <button>Hover me</button>
      </Tooltip>
    );
    
    const trigger = screen.getByRole('button');
    fireEvent.mouseEnter(trigger.parentElement!);
    
    expect(screen.getByText('Tooltip text')).toBeInTheDocument();
    
    fireEvent.mouseLeave(trigger.parentElement!);
    
    expect(screen.queryByText('Tooltip text')).not.toBeInTheDocument();
  });

  it('renders with different positions', () => {
    const { rerender } = render(
      <Tooltip content="Top tooltip" position="top">
        <span>Trigger</span>
      </Tooltip>
    );
    
    fireEvent.mouseEnter(screen.getByText('Trigger').parentElement!);
    expect(screen.getByText('Top tooltip')).toBeInTheDocument();
    
    rerender(
      <Tooltip content="Bottom tooltip" position="bottom">
        <span>Trigger</span>
      </Tooltip>
    );
    
    fireEvent.mouseEnter(screen.getByText('Trigger').parentElement!);
    expect(screen.getByText('Bottom tooltip')).toBeInTheDocument();
  });
});
