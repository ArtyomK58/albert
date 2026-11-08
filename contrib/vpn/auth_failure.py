"""Turn private authentication responses into fixed, non-secret diagnostic tags."""

AUTH_FAILURE_TAGS = {
    'auth-failure', 'auth-credentials-rejected', 'auth-mfa-timeout',
    'auth-session-expired', 'auth-session-limit', 'auth-client-policy',
    'auth-account-locked', 'auth-cipher-negotiation', 'auth-interactive-challenge',
}


def auth_failure_code(line):
    low = bytes(line).lower()
    if b'crv1:' in low or b'cr_text:' in low:
        return 'auth-interactive-challenge'
    if b'cipher' in low and (b'negotiation' in low or b'shared' in low):
        return 'auth-cipher-negotiation'
    if any(text in low for text in [b'account locked', b'account is locked', b'account disabled']):
        return 'auth-account-locked'
    if any(text in low for text in [b'maximum concurrent', b'maximum sessions', b'already connected', b'session limit']):
        return 'auth-session-limit'
    if any(text in low for text in [b'unsupported client', b'client version', b'device posture']):
        return 'auth-client-policy'
    if b'token expired' in low or b'session expired' in low:
        return 'auth-session-expired'
    if (b'mfa' in low or b'multi-factor' in low or b'multifactor' in low) and (b'timeout' in low or b'timed out' in low):
        return 'auth-mfa-timeout'
    if any(text in low for text in [b'invalid password', b'invalid credentials', b'username/password verification failed']):
        return 'auth-credentials-rejected'
    return 'auth-failure'
