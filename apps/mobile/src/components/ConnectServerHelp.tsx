import React from 'react';
import { config } from '../config';
import type { Organization } from '../lib/api';
import { Body, Code, EmptyState, LinkText } from './ui';

/** Honest "nothing here yet" for an org with no registered servers. */
export function ConnectServerHelp({ org }: { org: Organization }) {
  return (
    <EmptyState title="No servers connected yet">
      <Body>
        {org.name} has no servers registered. Add one on the web dashboard, then install the ThreatCrush
        daemon on it:
      </Body>
      <LinkText label="Add a server" url={`${config.apiUrl}/org/${org.slug}/servers/new`} />
      <Code>{'curl -fsSL https://threatcrush.com/install.sh | sh\nthreatcrush login\nthreatcrush init'}</Code>
      <Body>Pull down to refresh once it's added.</Body>
    </EmptyState>
  );
}
