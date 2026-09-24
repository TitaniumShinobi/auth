#!/usr/bin/env node
/** Verify recorded evidence, not a running authentication service. */
export function verifyLifecycle(trace) {
  const failures = [];
  let incomplete = false;
  const requireEvidence = (condition) => { if (!condition) incomplete = true; };
  const fail = (condition, message) => { if (condition) failures.push(message); };
  if (!trace || !Array.isArray(trace.events) || trace.events.length === 0) {
    return { verification: 'INDETERMINATE', failures };
  }
  const known = new Set(['identity.lookup', 'identity.create', 'identity.authenticate', 'authentication.denied',
    'enrollment.decision', 'primary.complete', 'primary.blocked', 'account.link', 'relying-party.accept',
    'magic.consume', 'session.issue', 'session.validate', 'session.refresh', 'session.logout', 'session.revoke', 'session.expire']);
  const events = trace.events.filter(event => {
    if (!event || typeof event !== 'object' || !known.has(event.type)) { incomplete = true; return false; }
    return true;
  });
  const all = type => events.filter(event => event.type === type);
  const hasId = value => typeof value === 'string' && value.length > 0;
  const created = all('identity.create');
  const authenticated = all('identity.authenticate');
  fail(all('authentication.denied').length > 0 &&
    (authenticated.length > 0 || all('session.issue').some(event => event.success === true)),
  'An atomic trace cannot deny authentication while authenticating identity or issuing a session.');
  for (const event of [...created, ...authenticated]) requireEvidence(hasId(event.id));
  switch (trace.capability) {
    case 'login':
    case 'signup': {
      const lookup = all('identity.lookup');
      requireEvidence(lookup.length === 1 && typeof lookup[0]?.exists === 'boolean');
      const existing = lookup[0]?.exists;
      if (lookup.length === 1) {
        fail([...created, ...authenticated].some(event => events.indexOf(event) < events.indexOf(lookup[0])),
          'Identity lookup must precede identity creation or authentication.');
      }
      if (existing === true) requireEvidence(hasId(lookup[0].id));
      fail(trace.capability === 'login' && created.length > 0, 'Login must not create an identity.');
      fail(existing === true && created.length > 0, 'An existing identity must not be duplicated during signup or login.');
      fail(created.length > 1, 'A signup must not create multiple identities.');
      if (existing === true) {
        requireEvidence(authenticated.length > 0 || all('authentication.denied').length > 0);
        fail(authenticated.some(event => hasId(event.id) && hasId(lookup[0].id) && event.id !== lookup[0].id), 'Authentication must reuse the existing identity.');
      } else if (existing === false && trace.capability === 'signup') {
        requireEvidence(created.length === 1 && authenticated.length > 0);
        fail(authenticated.some(event => created[0]?.id && event.id !== created[0].id), 'Signup must authenticate the created identity.');
      } else if (existing === false) {
        requireEvidence(all('authentication.denied').length > 0);
        fail(authenticated.length > 0, 'Login cannot authenticate a nonexistent identity.');
      }
      break;
    }
    case 'optional-enrollment': {
      const decisions = all('enrollment.decision');
      requireEvidence(decisions.length > 0 && decisions.every(event => event.optional === true && typeof event.accepted === 'boolean'));
      requireEvidence(all('primary.complete').length > 0);
      fail(decisions.some(event => event.optional === true && event.accepted === false) && all('primary.blocked').length > 0,
        'Declining optional enrollment must not block primary completion.');
      break;
    }
    case 'account-link': {
      const links = all('account.link');
      requireEvidence(links.length > 0 && links.every(event => hasId(event.existingId) && hasId(event.linkedId)));
      fail(created.length > 0, 'Linking an existing account must not create an identity.');
      fail(links.some(event => hasId(event.existingId) && hasId(event.linkedId) && event.existingId !== event.linkedId), 'Account linking must reuse the existing identity.');
      break;
    }
    case 'relying-party': {
      const accepted = all('relying-party.accept');
      requireEvidence(accepted.length > 0 && accepted.every(event => typeof event.identityAuthority === 'boolean'));
      fail(accepted.some(event => event.identityAuthority === true) || created.length > 0, 'A relying party must not act as identity authority.');
      break;
    }
    case 'magic-email': {
      const consumed = all('magic.consume');
      const outcomes = new Set(['valid', 'expired', 'replayed', 'delivery-failed']);
      requireEvidence(consumed.length === 1 && outcomes.has(consumed[0]?.outcome));
      if (consumed[0]?.outcome === 'valid') {
        requireEvidence(authenticated.length > 0 || all('authentication.denied').length > 0);
        fail(authenticated.some(event => events.indexOf(event) < events.indexOf(consumed[0])), 'Magic-link verification must precede authentication.');
      }
      if (consumed.some(event => ['expired', 'replayed', 'delivery-failed'].includes(event.outcome))) {
        fail(authenticated.length > 0 || all('session.issue').some(event => event.success === true), 'An expired, replayed, or undelivered magic link must not authenticate.');
        requireEvidence(all('authentication.denied').length > 0);
      }
      break;
    }
    case 'session': {
      const sessions = events.filter(event => event.type.startsWith('session.'));
      requireEvidence(sessions.length > 0);
      for (const event of sessions) {
        requireEvidence(hasId(event.sessionId) && typeof event.success === 'boolean');
        fail(event.success === false, `${event.type} did not succeed.`);
      }
      break;
    }
    default: incomplete = true;
  }
  return { verification: failures.length ? 'FAIL' : incomplete ? 'INDETERMINATE' : 'PASS', failures };
}
