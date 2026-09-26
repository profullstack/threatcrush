import { describe, expect, it } from 'vitest';
import { signInStep } from '../init.js';

describe('signInStep', () => {
  const fresh = { loggedIn: false, interactive: true };

  it('asks a person at a terminal', () => {
    expect(signInStep(fresh)).toBe('ask');
  });

  it('skips sign-in without a terminal instead of waiting on an unanswerable prompt', () => {
    // `init </dev/null`, a pipe, CI: nobody can type a password.
    expect(signInStep({ ...fresh, interactive: false })).toBe('skip-noninteractive');
    expect(signInStep({ ...fresh, interactive: false, yes: true })).toBe('skip-noninteractive');
  });

  it('--offline skips sign-in even at a terminal', () => {
    expect(signInStep({ ...fresh, offline: true })).toBe('skip-offline');
    expect(signInStep({ ...fresh, offline: true, yes: true })).toBe('skip-offline');
  });

  it('--yes goes straight to the credentials at a terminal', () => {
    expect(signInStep({ ...fresh, yes: true })).toBe('sign-in');
  });

  it('an existing session wins over every flag', () => {
    expect(signInStep({ loggedIn: true, interactive: false, offline: true })).toBe('signed-in');
  });
});
