'use strict';

class VLockError extends Error {
  constructor(message, { code = 'ERR_VLOCK', details, cause } = {}) {
    super(String(message), cause === undefined ? undefined : { cause });
    this.name = new.target.name;
    this.code = code;
    if (details !== undefined) {
      this.details = Object.freeze({ ...details });
    }
    Error.captureStackTrace?.(this, new.target);
  }
}

class CodecError extends VLockError {
  constructor(message, options = {}) {
    super(message, { code: 'ERR_VLOCK_CODEC', ...options });
  }
}

class ValidationError extends VLockError {
  constructor(message, options = {}) {
    super(message, { code: 'ERR_VLOCK_VALIDATION', ...options });
  }
}

class CryptoError extends VLockError {
  constructor(message, options = {}) {
    super(message, { code: 'ERR_VLOCK_CRYPTO', ...options });
  }
}

class StateError extends VLockError {
  constructor(message, options = {}) {
    super(message, { code: 'ERR_VLOCK_STATE', ...options });
  }
}

class TransitionError extends StateError {
  constructor(message, options = {}) {
    super(message, { code: 'ERR_VLOCK_TRANSITION', ...options });
  }
}

class PccError extends VLockError {
  constructor(message, options = {}) {
    super(message, { code: 'ERR_VLOCK_PCC', ...options });
  }
}

module.exports = Object.freeze({
  VLockError,
  CodecError,
  ValidationError,
  CryptoError,
  StateError,
  TransitionError,
  PccError,
});
