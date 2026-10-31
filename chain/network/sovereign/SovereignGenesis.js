'use strict';

const { createHash } = require('node:crypto');
const {
  GlobalState,
  NETWORK_ID,
  UNIT,
  MAX_U128,
  crypto: vlockCrypto,
} = require('../../vlock7sin-js/src');
const { canonicalBytes, compareUtf8 } = require('../../vlock7sin-js/src/causalGraph');
const { publicKeyObject } = require('../../vlock7sin-js/src/quorum');
const { normalizePublicIdentity } = require('../../vlock7sin-js/src/hybridCrypto');
const { validateKoPolicy } = require('../../vlock7sin-js/src/koPolicy');
const { KoGlobalState } = require('../../vlock7sin-js/src/koState');
const { FORMAT: KO_PROGRAM_FORMAT, PROTOCOL: KO_PROGRAM_PROTOCOL, PROFILE: KO_PROGRAM_PROFILE,
  AUTHORIZED_FORMAT, AUTHORIZED_PROTOCOL, AUTHORIZED_PROFILE, normalizeDeploymentPolicy } = require('../../vlock7sin-js/src/koConsensusProfile');

const FORMAT = 'konaet-sovereign-genesis-v1';
const HYBRID_FORMAT = 'konaet-sovereign-genesis-v2-hybrid';
const HYBRID_TRANSFER_FORMAT = 'konaet-sovereign-genesis-v3-hybrid-transfer';
const HYBRID_TRANSPORT_FORMAT = 'konaet-sovereign-genesis-v4-hybrid-transport';
const HYBRID_BINARY_TRANSPORT_FORMAT = 'konaet-sovereign-genesis-v5-hybrid-transport-binary';
const KO_POLICY_FORMAT = 'konaet-sovereign-genesis-v6-ko-policy';
const KO_PROTOCOL_VERSION = '0.5.0-sovereign-ko.1';
const ED25519_PROFILE = 'ED25519_V1';
const HYBRID_PROFILE = 'ED25519_AND_ML_DSA_65_V1';
const HYBRID_TRANSFER_PROFILE = 'ED25519_AND_ML_DSA_65_TRANSFER_V1';
const HYBRID_TRANSPORT_PROFILE = 'ED25519_AND_ML_DSA_65_TRANSPORT_V1';
const HYBRID_BINARY_TRANSPORT_PROFILE = 'ED25519_AND_ML_DSA_65_TRANSPORT_BINARY_V2';
const DEFAULT_PROTOCOL_VERSION = '0.2.0-sovereign-devnet.2';
const DEFAULT_HYBRID_PROTOCOL_VERSION = '0.3.0-sovereign-hybrid-devnet.1';
const DEFAULT_HYBRID_TRANSFER_PROTOCOL_VERSION = '0.3.0-sovereign-hybrid-devnet.2';
const DEFAULT_HYBRID_TRANSPORT_PROTOCOL_VERSION = '0.3.0-sovereign-hybrid-devnet.3';
const DEFAULT_HYBRID_BINARY_TRANSPORT_PROTOCOL_VERSION = '0.4.0-sovereign-hybrid-devnet.4';
const DOMAIN_GENESIS = Buffer.from('KONAET/SOVEREIGN/GENESIS/v1\0', 'ascii');
const DOMAIN_HYBRID_GENESIS = Buffer.from('KONAET/SOVEREIGN/GENESIS/v2-hybrid\0', 'ascii');
const DOMAIN_HYBRID_TRANSFER_GENESIS = Buffer.from('KONAET/SOVEREIGN/GENESIS/v3-hybrid-transfer\0', 'ascii');
const DOMAIN_HYBRID_TRANSPORT_GENESIS = Buffer.from('KONAET/SOVEREIGN/GENESIS/v4-hybrid-transport\0', 'ascii');
const DOMAIN_HYBRID_BINARY_TRANSPORT_GENESIS = Buffer.from('KONAET/SOVEREIGN/GENESIS/v5-hybrid-transport-binary\0', 'ascii');
const DOMAIN_KO_GENESIS = Buffer.from('KONAET/SOVEREIGN/GENESIS/v6-ko-policy\0', 'ascii');
const DOMAIN_PARAMETERS = Buffer.from('KONAET/SOVEREIGN/PARAMETERS/v1\0', 'ascii');
const DOMAIN_IDENTITIES = Buffer.from('KONAET/SOVEREIGN/IDENTITIES/v1\0', 'ascii');
const DOMAIN_REPLAY = Buffer.from('KONAET/SOVEREIGN/REPLAY/v1\0', 'ascii');
const EXACT_FIELDS = Object.freeze([
  'format', 'genesisId', 'networkId', 'protocolVersion', 'chainName', 'createdAt',
  'asset', 'validators', 'threshold', 'allocations', 'parameters', 'parametersRoot',
  'identitiesRoot', 'replayRoot', 'stateRoot',
]);
const HYBRID_EXACT_FIELDS = Object.freeze([
  ...EXACT_FIELDS.slice(0, 6), 'consensusSignatureProfile', ...EXACT_FIELDS.slice(6),
]);
const HYBRID_TRANSFER_EXACT_FIELDS = Object.freeze([
  ...EXACT_FIELDS.slice(0, 6), 'consensusSignatureProfile', 'transferAuthorizationProfile', ...EXACT_FIELDS.slice(6),
]);
const HYBRID_TRANSPORT_EXACT_FIELDS = Object.freeze([
  ...EXACT_FIELDS.slice(0, 6), 'consensusSignatureProfile', 'transferAuthorizationProfile',
  'transportSignatureProfile', ...EXACT_FIELDS.slice(6),
]);
const KO_EXACT_FIELDS = Object.freeze([
  ...EXACT_FIELDS.slice(0, 6), 'consensusSignatureProfile', 'transferAuthorizationProfile',
  'transportSignatureProfile', 'nativePolicy', ...EXACT_FIELDS.slice(6),
]);
const KO_PROGRAM_EXACT_FIELDS = Object.freeze([...KO_EXACT_FIELDS, 'contractRuntime']);
const AUTHORIZED_EXACT_FIELDS = Object.freeze([...KO_PROGRAM_EXACT_FIELDS, 'deploymentPolicy']);

class SovereignGenesisError extends Error {
  constructor(code, message, details = undefined) {
    super(message);
    this.name = 'SovereignGenesisError';
    this.code = code;
    if (details !== undefined) this.details = details;
  }
}

function hash(domain, value) {
  return createHash('sha3-256').update(domain).update(canonicalBytes(value)).digest('hex');
}

function exactObject(value, fields, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new SovereignGenesisError('INVALID_GENESIS', `${label} must be an object.`);
  }
  const actual = Object.keys(value).sort(compareUtf8);
  const expected = [...fields].sort(compareUtf8);
  if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) {
    throw new SovereignGenesisError('INVALID_GENESIS', `${label} has missing or unexpected fields.`);
  }
}

function safeId(value, label, maximum = 128) {
  const text = String(value ?? '').normalize('NFC');
  if (!new RegExp(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,${maximum - 1}}$`).test(text)) {
    throw new SovereignGenesisError('INVALID_GENESIS', `${label} must be safe ASCII.`);
  }
  return text;
}

function safeText(value, label, maximum = 128) {
  const text = String(value ?? '').normalize('NFC').trim();
  const hasControl = [...text].some((character) => {
    const code = character.codePointAt(0);
    return code <= 31 || code === 127;
  });
  if (!text || Buffer.byteLength(text, 'utf8') > maximum || hasControl) {
    throw new SovereignGenesisError('INVALID_GENESIS', `${label} is invalid.`);
  }
  return text;
}

function u32(value, label) {
  const number = Number(value);
  if (!Number.isSafeInteger(number) || number < 1 || number > 0xffffffff) {
    throw new SovereignGenesisError('INVALID_GENESIS', `${label} must be a non-zero u32.`);
  }
  return number;
}

function boundedInteger(value, label, minimum, maximum) {
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new SovereignGenesisError('INVALID_GENESIS', `${label} must be ${minimum}..${maximum}.`);
  }
  return value;
}

function atomicString(value, label) {
  if (typeof value !== 'string' && typeof value !== 'bigint') {
    throw new SovereignGenesisError('INVALID_GENESIS', `${label} must be an exact integer string.`);
  }
  const text = String(value);
  if (!/^(?:0|[1-9][0-9]*)$/.test(text)) {
    throw new SovereignGenesisError('INVALID_GENESIS', `${label} must be canonical unsigned decimal.`);
  }
  const amount = BigInt(text);
  if (amount < 1n || amount > MAX_U128) {
    throw new SovereignGenesisError('INVALID_GENESIS', `${label} is outside u128.`);
  }
  return amount.toString(10);
}

function rawPublicKeyHex(value) {
  try {
    const key = publicKeyObject(value);
    if (key.asymmetricKeyType !== 'ed25519') throw new Error('not Ed25519');
    return vlockCrypto.rawPublicKey(key).toString('hex');
  } catch (error) {
    throw new SovereignGenesisError('INVALID_VALIDATOR_KEY', 'Validator public key must be Ed25519.', {
      cause: error.message,
    });
  }
}

function normalizeValidators(input, consensusSignatureProfile, transportSignatureProfile = null) {
  if (!Array.isArray(input) || input.length < 4 || input.length > 100) {
    throw new SovereignGenesisError('INVALID_VALIDATORS', 'A sovereign devnet requires 4..100 validators.');
  }
  const validators = input.map((validator) => {
    exactObject(validator, consensusSignatureProfile === HYBRID_PROFILE
      ? ['id', 'publicKey', 'publicIdentity'] : ['id', 'publicKey'], 'validator');
    const normalized = {
      id: safeId(validator.id, 'validator id'),
      publicKey: rawPublicKeyHex(validator.publicKey),
    };
    if (consensusSignatureProfile === HYBRID_PROFILE) {
      try {
        const hybrid = normalizePublicIdentity(validator.publicIdentity);
        if ([HYBRID_TRANSPORT_PROFILE, HYBRID_BINARY_TRANSPORT_PROFILE].includes(transportSignatureProfile)
          && vlockCrypto.rawPublicKey(hybrid.keys.ed25519).toString('hex') !== normalized.publicKey) {
          throw new Error('hybrid transport Ed25519 key differs from validator key');
        }
        normalized.publicIdentity = hybrid.identity;
      }
      catch (error) {
        throw new SovereignGenesisError('INVALID_HYBRID_VALIDATOR_IDENTITY', 'Hybrid validator identity is invalid.', {
          cause: error.message,
        });
      }
    }
    return Object.freeze(normalized);
  }).sort((left, right) => compareUtf8(left.id, right.id));
  if (new Set(validators.map(({ id }) => id)).size !== validators.length) {
    throw new SovereignGenesisError('DUPLICATE_VALIDATOR', 'Validator ids must be unique.');
  }
  if (new Set(validators.map(({ publicKey }) => publicKey)).size !== validators.length) {
    throw new SovereignGenesisError('DUPLICATE_VALIDATOR_KEY', 'Validator keys must be unique.');
  }
  if (consensusSignatureProfile === HYBRID_PROFILE
    && new Set(validators.map(({ publicIdentity }) => publicIdentity.fingerprint)).size !== validators.length) {
    throw new SovereignGenesisError('DUPLICATE_HYBRID_VALIDATOR_IDENTITY', 'Hybrid validator identities must be unique.');
  }
  return Object.freeze(validators);
}

function normalizeAllocations(input) {
  if (!Array.isArray(input) || input.length < 1 || input.length > 100000) {
    throw new SovereignGenesisError('INVALID_ALLOCATIONS', 'Genesis allocations must contain 1..100000 accounts.');
  }
  const allocations = input.map((allocation) => Object.freeze({
    address: vlockCrypto.validateAddress(allocation?.address),
    amountAtomic: atomicString(allocation?.amountAtomic, 'allocation amountAtomic'),
  })).sort((left, right) => compareUtf8(left.address, right.address));
  if (new Set(allocations.map(({ address }) => address)).size !== allocations.length) {
    throw new SovereignGenesisError('DUPLICATE_ALLOCATION', 'Genesis allocation addresses must be unique.');
  }
  const total = allocations.reduce((sum, allocation) => sum + BigInt(allocation.amountAtomic), 0n);
  if (total !== UNIT.initialSupplyAtomic) {
    throw new SovereignGenesisError(
      'SUPPLY_MISMATCH',
      `Genesis allocations must equal the fixed ${UNIT.symbol} supply.`,
      { expectedAtomic: UNIT.initialSupplyAtomic.toString(10), actualAtomic: total.toString(10) },
    );
  }
  return Object.freeze(allocations);
}

function normalizeParameters(input = {}) {
  return Object.freeze({
    maxActs: boundedInteger(input.maxActs ?? 1024, 'parameters.maxActs', 1, 10000),
    maxBytes: boundedInteger(input.maxBytes ?? 1024 * 1024, 'parameters.maxBytes', 1024, 8 * 1024 * 1024),
    stateSyncChunk: boundedInteger(input.stateSyncChunk ?? 16, 'parameters.stateSyncChunk', 1, 128),
    messageRateWindowMs: boundedInteger(input.messageRateWindowMs ?? 10000, 'parameters.messageRateWindowMs', 1000, 60000),
    messageRateLimit: boundedInteger(input.messageRateLimit ?? 256, 'parameters.messageRateLimit', 16, 4096),
  });
}

function canonicalCreatedAt(value) {
  const date = value instanceof Date ? value : new Date(value ?? Date.now());
  if (!Number.isFinite(date.getTime())) throw new SovereignGenesisError('INVALID_GENESIS', 'createdAt is invalid.');
  const iso = date.toISOString();
  if (value !== undefined && String(value) !== iso) {
    throw new SovereignGenesisError('INVALID_GENESIS', 'createdAt must be canonical ISO-8601 UTC.');
  }
  return iso;
}

function materialize(options) {
  const authorized = options.format === AUTHORIZED_FORMAT || options.contractRuntime?.deploymentAuthorization === AUTHORIZED_PROFILE.deploymentAuthorization;
  const programs = authorized || options.format === KO_PROGRAM_FORMAT || options.contractRuntime != null;
  const programProfile = authorized ? AUTHORIZED_PROFILE : KO_PROGRAM_PROFILE;
  const programProtocol = authorized ? AUTHORIZED_PROTOCOL : KO_PROGRAM_PROTOCOL;
  if (programs && !canonicalBytes(options.contractRuntime).equals(canonicalBytes(programProfile))) {
    throw new SovereignGenesisError('KO_PROGRAM_PROFILE_MISMATCH', 'Contract runtime must match the supported consensus profile.');
  }
  if (!authorized && options.deploymentPolicy != null) throw new SovereignGenesisError('KO_DEPLOYMENT_POLICY_VERSION', 'Deployment authorization requires a v8 genesis.');
  const deploymentPolicy = authorized ? normalizeDeploymentPolicy(options.deploymentPolicy) : null;
  const nativePolicy = options.nativePolicy == null ? null : validateKoPolicy(options.nativePolicy);
  if ((options.format === KO_POLICY_FORMAT || programs) && !nativePolicy) {
    throw new SovereignGenesisError('KO_POLICY_REQUIRED', 'The .ko genesis requires its executable source and commitments.');
  }
  const consensusSignatureProfile = options.consensusSignatureProfile
    ?? ([HYBRID_FORMAT, HYBRID_TRANSFER_FORMAT, HYBRID_TRANSPORT_FORMAT, HYBRID_BINARY_TRANSPORT_FORMAT]
      .includes(options.format) ? HYBRID_PROFILE : ED25519_PROFILE);
  const transferAuthorizationProfile = options.transferAuthorizationProfile ?? null;
  const transportSignatureProfile = options.transportSignatureProfile ?? null;
  if (consensusSignatureProfile !== ED25519_PROFILE && consensusSignatureProfile !== HYBRID_PROFILE) {
    throw new SovereignGenesisError('INVALID_SIGNATURE_PROFILE', 'Consensus signature profile is unsupported.');
  }
  if (transferAuthorizationProfile !== null && transferAuthorizationProfile !== HYBRID_TRANSFER_PROFILE) {
    throw new SovereignGenesisError('INVALID_TRANSFER_AUTHORIZATION_PROFILE', 'Transfer authorization profile is unsupported.');
  }
  if (transferAuthorizationProfile && consensusSignatureProfile !== HYBRID_PROFILE) {
    throw new SovereignGenesisError('INVALID_TRANSFER_AUTHORIZATION_PROFILE', 'Hybrid transfer authorization requires hybrid consensus identities.');
  }
  if (transportSignatureProfile !== null
    && ![HYBRID_TRANSPORT_PROFILE, HYBRID_BINARY_TRANSPORT_PROFILE].includes(transportSignatureProfile)) {
    throw new SovereignGenesisError('INVALID_TRANSPORT_SIGNATURE_PROFILE', 'Transport signature profile is unsupported.');
  }
  if (transportSignatureProfile && (consensusSignatureProfile !== HYBRID_PROFILE
    || transferAuthorizationProfile !== HYBRID_TRANSFER_PROFILE)) {
    throw new SovereignGenesisError('INVALID_TRANSPORT_SIGNATURE_PROFILE', 'Hybrid transport requires hybrid consensus and transfer authorization.');
  }
  if (programs && (consensusSignatureProfile !== ED25519_PROFILE || transferAuthorizationProfile || transportSignatureProfile)) {
    throw new SovereignGenesisError('KO_PROGRAM_SIGNATURE_PROFILE', 'Contract consensus currently requires the Ed25519 identity profile.');
  }
  const expectedFormat = authorized ? AUTHORIZED_FORMAT : programs ? KO_PROGRAM_FORMAT : nativePolicy ? KO_POLICY_FORMAT
    : transportSignatureProfile === HYBRID_BINARY_TRANSPORT_PROFILE ? HYBRID_BINARY_TRANSPORT_FORMAT
      : transportSignatureProfile ? HYBRID_TRANSPORT_FORMAT : transferAuthorizationProfile ? HYBRID_TRANSFER_FORMAT
        : consensusSignatureProfile === HYBRID_PROFILE ? HYBRID_FORMAT : FORMAT;
  if (options.format !== undefined && options.format !== expectedFormat) {
    throw new SovereignGenesisError('INVALID_SIGNATURE_PROFILE', 'Genesis format and signature profile do not match.');
  }
  const networkId = u32(options.networkId ?? NETWORK_ID, 'networkId');
  const protocolVersion = safeId(options.protocolVersion
    ?? (programs ? programProtocol : nativePolicy ? KO_PROTOCOL_VERSION
      : transportSignatureProfile === HYBRID_BINARY_TRANSPORT_PROFILE ? DEFAULT_HYBRID_BINARY_TRANSPORT_PROTOCOL_VERSION
        : transportSignatureProfile ? DEFAULT_HYBRID_TRANSPORT_PROTOCOL_VERSION
          : transferAuthorizationProfile ? DEFAULT_HYBRID_TRANSFER_PROTOCOL_VERSION
            : consensusSignatureProfile === HYBRID_PROFILE ? DEFAULT_HYBRID_PROTOCOL_VERSION : DEFAULT_PROTOCOL_VERSION), 'protocolVersion', 32);
  if ((programs && protocolVersion !== programProtocol)
    || (!programs && ((nativePolicy && protocolVersion !== KO_PROTOCOL_VERSION)
      || (!nativePolicy && [KO_PROTOCOL_VERSION, KO_PROGRAM_PROTOCOL, AUTHORIZED_PROTOCOL].includes(protocolVersion))))) {
    throw new SovereignGenesisError('KO_PROTOCOL_MISMATCH', 'The .ko protocol and policy must be activated together.');
  }
  const validators = normalizeValidators(options.validators, consensusSignatureProfile, transportSignatureProfile);
  const minimumThreshold = Math.floor((2 * validators.length) / 3) + 1;
  const threshold = boundedInteger(options.threshold ?? minimumThreshold, 'threshold', minimumThreshold, validators.length);
  const allocations = normalizeAllocations(options.allocations);
  const parameters = normalizeParameters(programs ? { ...options.parameters,
    maxActs: options.parameters?.maxActs ?? KO_PROGRAM_PROFILE.actsPerClosure,
    maxBytes: options.parameters?.maxBytes ?? KO_PROGRAM_PROFILE.closureBytes } : options.parameters);
  if (programs && (parameters.maxActs > KO_PROGRAM_PROFILE.actsPerClosure || parameters.maxBytes > KO_PROGRAM_PROFILE.closureBytes)) {
    throw new SovereignGenesisError('KO_PROGRAM_CLOSURE_LIMIT', 'v7 closure limits exceed the supported contract profile.');
  }
  const asset = Object.freeze({
    name: UNIT.name,
    symbol: UNIT.symbol,
    atomicName: UNIT.atomicName,
    decimals: UNIT.decimals,
    fixedSupplyAtomic: UNIT.initialSupplyAtomic.toString(10),
  });
  const base = {
    format: expectedFormat,
    networkId: String(networkId),
    protocolVersion,
    chainName: safeText(options.chainName ?? 'Konaet VLOCK7SIN Sovereign Devnet', 'chainName', 96),
    createdAt: canonicalCreatedAt(options.createdAt),
    asset,
    validators,
    threshold,
    allocations,
    parameters,
  };
  if (consensusSignatureProfile === HYBRID_PROFILE) base.consensusSignatureProfile = HYBRID_PROFILE;
  if (transferAuthorizationProfile) base.transferAuthorizationProfile = transferAuthorizationProfile;
  if (transportSignatureProfile) base.transportSignatureProfile = transportSignatureProfile;
  if (nativePolicy) Object.assign(base, { consensusSignatureProfile, transferAuthorizationProfile, transportSignatureProfile, nativePolicy });
  if (programs) base.contractRuntime = programProfile;
  if (authorized) base.deploymentPolicy = deploymentPolicy;
  const parametersRoot = hash(DOMAIN_PARAMETERS, { networkId: base.networkId, protocolVersion, asset, parameters,
    ...(nativePolicy ? { nativePolicy: { profile: nativePolicy.profile, sourceSha256: nativePolicy.sourceSha256,
      programSha256: nativePolicy.programSha256 } } : {}),
    ...(programs ? { contractRuntime: programProfile } : {}),
    ...(authorized ? { deploymentPolicy } : {}),
  });
  const identitiesRoot = hash(DOMAIN_IDENTITIES, { networkId: base.networkId, validators, threshold });
  const replayRoot = hash(DOMAIN_REPLAY, { networkId: base.networkId, protocolVersion, createdAt: base.createdAt });
  const State = programs ? KoGlobalState : GlobalState;
  const state = new State({
    ...(authorized ? { deploymentPolicy } : {}),
    networkId,
    balances: allocations.map(({ address, amountAtomic }) => [address, BigInt(amountAtomic)]),
    parametersRoot,
    identitiesRoot,
    replayRoot,
  });
  const body = Object.freeze({
    ...base,
    parametersRoot,
    identitiesRoot,
    replayRoot,
    stateRoot: state.root().toString('hex'),
  });
  return { body, state, genesisId: hash(
    authorized ? Buffer.from('KONAET/SOVEREIGN/GENESIS/v8-ko-admission\0', 'ascii') : programs ? Buffer.from('KONAET/SOVEREIGN/GENESIS/v7-ko-program\0', 'ascii') : nativePolicy ? DOMAIN_KO_GENESIS
      : transportSignatureProfile === HYBRID_BINARY_TRANSPORT_PROFILE ? DOMAIN_HYBRID_BINARY_TRANSPORT_GENESIS
        : transportSignatureProfile ? DOMAIN_HYBRID_TRANSPORT_GENESIS
          : transferAuthorizationProfile ? DOMAIN_HYBRID_TRANSFER_GENESIS
            : consensusSignatureProfile === HYBRID_PROFILE ? DOMAIN_HYBRID_GENESIS : DOMAIN_GENESIS,
    body,
  ) };
}

function createGenesis(options = {}) {
  const { body, genesisId } = materialize(options);
  return Object.freeze({ ...body, genesisId });
}

function validateGenesis(genesis) {
  const authorized = genesis?.format === AUTHORIZED_FORMAT;
  const programs = authorized || genesis?.format === KO_PROGRAM_FORMAT;
  const koNative = genesis?.format === KO_POLICY_FORMAT || programs;
  const binaryTransportHybrid = genesis?.format === HYBRID_BINARY_TRANSPORT_FORMAT
    || (koNative && genesis.transportSignatureProfile === HYBRID_BINARY_TRANSPORT_PROFILE);
  const transportHybrid = genesis?.format === HYBRID_TRANSPORT_FORMAT || binaryTransportHybrid;
  const transferHybrid = genesis?.format === HYBRID_TRANSFER_FORMAT || transportHybrid
    || (koNative && genesis.transferAuthorizationProfile === HYBRID_TRANSFER_PROFILE);
  const hybrid = genesis?.format === HYBRID_FORMAT || transferHybrid
    || (koNative && genesis.consensusSignatureProfile === HYBRID_PROFILE);
  exactObject(genesis, authorized ? AUTHORIZED_EXACT_FIELDS : programs ? KO_PROGRAM_EXACT_FIELDS : koNative ? KO_EXACT_FIELDS : transportHybrid ? HYBRID_TRANSPORT_EXACT_FIELDS
    : transferHybrid ? HYBRID_TRANSFER_EXACT_FIELDS : hybrid ? HYBRID_EXACT_FIELDS : EXACT_FIELDS, 'genesis');
  if (hybrid && genesis.consensusSignatureProfile !== HYBRID_PROFILE) {
    throw new SovereignGenesisError('INVALID_SIGNATURE_PROFILE', 'Hybrid genesis signature profile is unsupported.');
  }
  if (transferHybrid && genesis.transferAuthorizationProfile !== HYBRID_TRANSFER_PROFILE) {
    throw new SovereignGenesisError('INVALID_TRANSFER_AUTHORIZATION_PROFILE', 'Hybrid transfer authorization profile is unsupported.');
  }
  if (transportHybrid && genesis.transportSignatureProfile !== (binaryTransportHybrid
    ? HYBRID_BINARY_TRANSPORT_PROFILE : HYBRID_TRANSPORT_PROFILE)) {
    throw new SovereignGenesisError('INVALID_TRANSPORT_SIGNATURE_PROFILE', 'Hybrid transport signature profile is unsupported.');
  }
  if (!hybrid && !koNative && genesis?.format !== FORMAT) {
    throw new SovereignGenesisError('INVALID_GENESIS_FORMAT', 'Genesis format is unsupported.');
  }
  exactObject(genesis.asset, ['name', 'symbol', 'atomicName', 'decimals', 'fixedSupplyAtomic'], 'asset');
  for (const validator of genesis.validators || []) exactObject(validator,
    hybrid ? ['id', 'publicKey', 'publicIdentity'] : ['id', 'publicKey'], 'validator');
  for (const allocation of genesis.allocations || []) exactObject(allocation, ['address', 'amountAtomic'], 'allocation');
  exactObject(genesis.parameters, ['maxActs', 'maxBytes', 'stateSyncChunk', 'messageRateWindowMs', 'messageRateLimit'], 'parameters');
  const rebuilt = createGenesis(genesis);
  if (!canonicalBytes(rebuilt).equals(canonicalBytes(genesis))) {
    throw new SovereignGenesisError('GENESIS_MISMATCH', 'Genesis fields, roots or id are not canonical.');
  }
  return rebuilt;
}

function stateFromGenesis(genesis) {
  const canonical = validateGenesis(genesis);
  const State = [KO_PROGRAM_FORMAT, AUTHORIZED_FORMAT].includes(canonical.format) ? KoGlobalState : GlobalState;
  return new State({
    ...(canonical.deploymentPolicy ? { deploymentPolicy: canonical.deploymentPolicy } : {}),
    networkId: Number(canonical.networkId),
    balances: canonical.allocations.map(({ address, amountAtomic }) => [address, BigInt(amountAtomic)]),
    parametersRoot: canonical.parametersRoot,
    identitiesRoot: canonical.identitiesRoot,
    replayRoot: canonical.replayRoot,
  });
}

module.exports = Object.freeze({
  KO_PROGRAM_FORMAT,
  AUTHORIZED_FORMAT,
  AUTHORIZED_PROTOCOL,
  KO_PROGRAM_PROTOCOL,
  KO_POLICY_FORMAT,
  KO_PROTOCOL_VERSION,
  FORMAT,
  HYBRID_FORMAT,
  HYBRID_TRANSFER_FORMAT,
  HYBRID_TRANSPORT_FORMAT,
  HYBRID_BINARY_TRANSPORT_FORMAT,
  ED25519_PROFILE,
  HYBRID_PROFILE,
  HYBRID_TRANSFER_PROFILE,
  HYBRID_TRANSPORT_PROFILE,
  HYBRID_BINARY_TRANSPORT_PROFILE,
  DEFAULT_PROTOCOL_VERSION,
  DEFAULT_HYBRID_PROTOCOL_VERSION,
  DEFAULT_HYBRID_TRANSFER_PROTOCOL_VERSION,
  DEFAULT_HYBRID_TRANSPORT_PROTOCOL_VERSION,
  DEFAULT_HYBRID_BINARY_TRANSPORT_PROTOCOL_VERSION,
  SovereignGenesisError,
  createGenesis,
  validateGenesis,
  stateFromGenesis,
});
