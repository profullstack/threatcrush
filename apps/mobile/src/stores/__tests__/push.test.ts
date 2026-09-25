import { beforeEach, describe, expect, it } from 'vitest';
import { useAuthStore } from '../auth';
import { ANDROID_CHANNEL_ID, usePushStore } from '../push';
import { mockHttp } from '../../__tests__/helpers/http';
import { notifications, platform } from '../../__tests__/helpers/native';

const EXPO_TOKEN = 'ExponentPushToken[device-1]';
const SUBS = 'POST /api/orgs/org-a/push-subscriptions';

describe('push store', () => {
  beforeEach(() => {
    usePushStore.setState({ status: 'unknown', token: null, orgId: null, error: null, dismissed: false });
    useAuthStore.setState({
      status: 'signedIn',
      session: {
        accessToken: 'access-1',
        refreshToken: 'refresh-1',
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
        userId: 'user-1',
        email: 'ops@example.com',
      },
    });
    notifications.getExpoPushTokenAsync.mockResolvedValue({ type: 'expo', data: EXPO_TOKEN });
  });

  it('registers silently for the org when permission was already granted', async () => {
    platform.OS = 'ios';
    notifications.getPermissionsAsync.mockResolvedValue({ status: 'granted', canAskAgain: true });
    const http = mockHttp({ [SUBS]: () => ({ body: { subscription: { id: 'sub-1' } } }) });

    await usePushStore.getState().sync('org-a');

    expect(notifications.requestPermissionsAsync).not.toHaveBeenCalled();
    expect(notifications.getExpoPushTokenAsync).toHaveBeenCalledWith({ projectId: 'eas-project-1' });
    expect(http.requests).toEqual([
      {
        method: 'POST',
        path: '/api/orgs/org-a/push-subscriptions',
        auth: 'Bearer access-1',
        body: { token: EXPO_TOKEN, platform: 'ios' },
      },
    ]);
    expect(usePushStore.getState()).toMatchObject({ status: 'enabled', token: EXPO_TOKEN, orgId: 'org-a' });
  });

  it('never prompts or registers on its own when permission is undecided', async () => {
    notifications.getPermissionsAsync.mockResolvedValue({ status: 'undetermined', canAskAgain: true });
    const http = mockHttp();

    await usePushStore.getState().sync('org-a');

    expect(notifications.requestPermissionsAsync).not.toHaveBeenCalled();
    expect(http.requests).toEqual([]);
    expect(usePushStore.getState().status).toBe('undetermined');
  });

  it('reports a hard denial so the UI can point at system settings', async () => {
    notifications.getPermissionsAsync.mockResolvedValue({ status: 'denied', canAskAgain: false });
    mockHttp();

    await usePushStore.getState().sync('org-a');
    expect(usePushStore.getState().status).toBe('denied');
  });

  it('asks only when the user opts in, creating the Android channel first', async () => {
    const order: string[] = [];
    notifications.setNotificationChannelAsync.mockImplementation(async (id: string) => {
      order.push(`channel:${id}`);
    });
    notifications.requestPermissionsAsync.mockImplementation(async () => {
      order.push('request');
      return { status: 'granted', canAskAgain: true };
    });
    notifications.getPermissionsAsync.mockResolvedValue({ status: 'granted', canAskAgain: true });
    const http = mockHttp({ [SUBS]: () => ({ body: { subscription: { id: 'sub-1' } } }) });

    await usePushStore.getState().enable('org-a');

    expect(order).toEqual([`channel:${ANDROID_CHANNEL_ID}`, 'request']);
    expect(http.requests[0].body).toEqual({ token: EXPO_TOKEN, platform: 'android' });
    expect(usePushStore.getState().status).toBe('enabled');
  });

  it('re-registers under the new org after an org switch', async () => {
    notifications.getPermissionsAsync.mockResolvedValue({ status: 'granted', canAskAgain: true });
    const http = mockHttp({
      [SUBS]: () => ({ body: { subscription: { id: 'sub-1' } } }),
      'POST /api/orgs/org-b/push-subscriptions': () => ({ body: { subscription: { id: 'sub-1' } } }),
    });

    await usePushStore.getState().sync('org-a');
    await usePushStore.getState().sync('org-a');
    await usePushStore.getState().sync('org-b');

    expect(http.requests.map((r) => r.path)).toEqual([
      '/api/orgs/org-a/push-subscriptions',
      '/api/orgs/org-b/push-subscriptions',
    ]);
    expect(usePushStore.getState().orgId).toBe('org-b');
  });

  it('shows the server error when registration fails', async () => {
    notifications.getPermissionsAsync.mockResolvedValue({ status: 'granted', canAskAgain: true });
    mockHttp({ [SUBS]: () => ({ status: 500, body: { error: 'Failed to register device' } }) });

    await usePushStore.getState().sync('org-a');

    expect(usePushStore.getState()).toMatchObject({ status: 'error', error: 'Failed to register device' });
  });

  it('unregisters the device token on sign-out', async () => {
    usePushStore.setState({ status: 'enabled', token: EXPO_TOKEN, orgId: 'org-a' });
    const http = mockHttp({
      'DELETE /api/orgs/org-a/push-subscriptions': () => ({ body: { success: true } }),
    });

    await usePushStore.getState().unregister();

    expect(http.requests).toEqual([
      {
        method: 'DELETE',
        path: '/api/orgs/org-a/push-subscriptions',
        auth: 'Bearer access-1',
        body: { token: EXPO_TOKEN },
      },
    ]);
    expect(usePushStore.getState()).toMatchObject({ status: 'unknown', token: null, orgId: null });
  });
});
