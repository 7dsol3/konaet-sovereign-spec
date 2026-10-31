'use strict';
const { createHash } = require('node:crypto');
const { encodeAddress, sign, verify } = require('./crypto');
const { ValidationError } = require('./errors');
const { PROFILE } = require('./koConsensusProfile');
const { runtime, auth, messages } = require('./koProgramRuntime');
const PREFIX = Buffer.from('VLOCK7SIN/KO-EVENT/v1\n', 'ascii');
function check(value, message) { if (!value) throw new ValidationError(message); }
function freeze(value) { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; }
function plain(value) {
  check(value && typeof value === 'object' && Object.getPrototypeOf(value) === Object.prototype && !Object.getOwnPropertySymbols(value).length, 'plain event object required');
  for (const descriptor of Object.values(Object.getOwnPropertyDescriptors(value))) check(descriptor.enumerable && Object.hasOwn(descriptor, 'value'), 'event accessors are forbidden');
  check(Object.keys(value).sort().join(',') === 'envelope,nonce,previousRoot,sequence,signature,source', 'unexpected contract event fields');
}
function decimal(value) { check(typeof value === 'string' && /^[1-9][0-9]{0,19}$/.test(value) && BigInt(value) <= 0xffffffffffffffffn, 'positive canonical u64 required'); return value; }
class ContractEvent {
  #body; #signature; #artifact; #contractId;
  constructor(input) {
    plain(input);
    const envelope = messages.envelope(input.envelope);
    check(envelope.payload.gasLimit <= PROFILE.gasPerTransaction, 'contract event gas exceeds consensus profile');
    const deploy = envelope.schema === messages.DEPLOY_SCHEMA;
    if (deploy) {
      check(typeof input.source === 'string' && Buffer.byteLength(input.source) <= PROFILE.sourceBytes, 'contract source exceeds consensus profile');
      this.#artifact = runtime.compileContract(input.source);
      const initial = auth.deploySignedContract(this.#artifact, envelope);
      this.#contractId = initial.state.contractId;
    } else {
      check(input.source === null, 'call events cannot carry replacement source');
      this.#artifact = null; this.#contractId = envelope.payload.contractId;
    }
    check(typeof input.previousRoot === 'string' && /^[0-9a-f]{64}$/.test(input.previousRoot), 'canonical previous root required');
    check(typeof input.signature === 'string' && (input.signature === '' || /^[0-9a-f]{128}$/.test(input.signature)), 'canonical outer signature required');
    this.#body = freeze({ envelope, source: input.source, sequence: decimal(input.sequence), nonce: decimal(input.nonce), previousRoot: input.previousRoot });
    this.#signature = input.signature;
    check(this.unsignedBytes().length + 143 <= PROFILE.transactionBytes, 'contract event exceeds byte limit');
    Object.freeze(this);
  }
  get format() { return PROFILE.eventFormat; }
  get kind() { return this.#artifact ? 'KONAET_KO_DEPLOY_V1' : 'KONAET_KO_CALL_V1'; }
  get networkId() { return Number(this.#body.envelope.payload.networkId); }
  get stateSuite() { return 1; }
  get sequence() { return BigInt(this.#body.sequence); }
  get nonce() { return BigInt(this.#body.nonce); }
  get previousRoot() { return Buffer.from(this.#body.previousRoot, 'hex'); }
  get senderPublicKey() { return Buffer.from(this.#body.envelope.publicKey, 'hex'); }
  get senderAddress() { return encodeAddress(this.senderPublicKey); }
  get nexuses() { return []; }
  get envelope() { return this.#body.envelope; }
  get artifact() { return this.#artifact; }
  get contractId() { return this.#contractId; }
  get signed() { return this.#signature.length === 128; }
  get locks() { return Object.freeze({ write: Object.freeze([`nonce:${this.senderAddress}`, `contract:${this.contractId}`]), read: Object.freeze([]) }); }
  unsignedBytes() { return Buffer.concat([PREFIX, Buffer.from(JSON.stringify(this.#body))]); }
  canonicalBytes() { check(this.signed, 'signed contract event required'); return Buffer.concat([PREFIX, Buffer.from(JSON.stringify({ ...this.#body, signature: this.#signature }))]); }
  transitionTrace() { return createHash('sha3-256').update('VLOCK7SIN/KO-TRACE/v1\0').update(this.unsignedBytes()).digest(); }
  id() { return createHash('sha3-256').update('VLOCK7SIN/KO-EVENT-ID/v1\0').update(this.canonicalBytes()).digest(); }
  sign(key) {
    const event = new ContractEvent({ ...this.#body, signature: sign(key, this.unsignedBytes()).toString('hex') });
    event.assertValid({ expectedNetworkId: this.networkId }); return event;
  }
  assertValid({ expectedNetworkId, expectedStateSuite = 1 } = {}) {
    check(this.networkId === expectedNetworkId && expectedStateSuite === this.stateSuite, 'contract event network or state suite mismatch');
    check(this.signed && verify(this.senderPublicKey, this.unsignedBytes(), Buffer.from(this.#signature, 'hex')), 'invalid outer contract signature');
    check(verify(this.senderPublicKey, Buffer.from(messages.signingText(this.#body.envelope.schema, this.#body.envelope.publicKey, this.#body.envelope.payload)), Buffer.from(this.#body.envelope.signature, 'hex')), 'invalid inner contract signature');
    return this;
  }
  verify(options) { try { this.assertValid(options); return true; } catch { return false; } }
  toJSON() { return { format: this.format, kind: this.kind, ...this.#body, signature: this.#signature, id: this.signed ? this.id().toString('hex') : null }; }
  static decode(value) {
    const bytes = Buffer.from(value);
    check(bytes.length <= PROFILE.transactionBytes && bytes.subarray(0, PREFIX.length).equals(PREFIX), 'invalid contract event wire format');
    const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes.subarray(PREFIX.length));
    const event = new ContractEvent(JSON.parse(text));
    check(event.canonicalBytes().equals(bytes), 'noncanonical contract event wire encoding'); return event;
  }
}
module.exports = Object.freeze({ ContractEvent, PREFIX });
