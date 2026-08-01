import React from 'react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';

import App from '../src/options/App.jsx';

describe('extension options app', () => {
  beforeEach(() => {
    global.chrome = {
      alarms: {
        create: vi.fn().mockResolvedValue(undefined),
      },
      storage: {
        local: {
          get: vi.fn((keys, callback) => callback({})),
          set: vi.fn().mockResolvedValue(undefined),
        },
      },
    };
  });

  it('normalizes a blank scan interval and reschedules the alarm on save', async () => {
    render(<App />);

    const intervalInput = screen.getByLabelText(/event check interval/i);
    fireEvent.change(intervalInput, { target: { value: '' } });
    fireEvent.click(screen.getByRole('button', { name: /save settings/i }));

    await waitFor(() => {
      expect(chrome.storage.local.set).toHaveBeenCalledWith(
        expect.objectContaining({ scanInterval: 5 })
      );
    });
    expect(chrome.alarms.create).toHaveBeenCalledWith('threatcrush-event-check', {
      periodInMinutes: 5,
    });
  });

  it('persists the selected scan interval and applies it to the event alarm', async () => {
    render(<App />);

    const intervalInput = screen.getByLabelText(/event check interval/i);
    fireEvent.change(intervalInput, { target: { value: '15' } });
    fireEvent.click(screen.getByRole('button', { name: /save settings/i }));

    await waitFor(() => {
      expect(chrome.storage.local.set).toHaveBeenCalledWith(
        expect.objectContaining({ scanInterval: 15 })
      );
    });
    expect(chrome.alarms.create).toHaveBeenCalledWith('threatcrush-event-check', {
      periodInMinutes: 15,
    });
  });
});
