'use strict';

const constants = require('./constants');
const errors = require('./errors');
const codec = require('./codec');
const crypto = require('./crypto');
const principle = require('./principle');
const event = require('./event');
const state = require('./state');
const pcc = require('./pcc');
const causalGraph = require('./causalGraph');
const constellation = require('./constellation');
const ledger = require('./ledger');
const quorum = require('./quorum');
const persistence = require('./persistence');
const network = require('./network');
const hybridCrypto = require('./hybridCrypto');
const hybridTransferAuthorization = require('./hybridTransferAuthorization');
const hybridQuorum = require('./hybridQuorum');
const privacy = require('./privacy');
const checkpoint = require('./checkpoint');
const actum = require('./actum');
const optimizer = require('./optimizer');

// Namespaces prevent ambiguous generic names; selected public APIs are also
// promoted for ergonomic CommonJS use (`const { GlobalState } = require(...)`).
module.exports = Object.freeze({
  constants,
  errors,
  codec,
  crypto,
  principle,
  event,
  state,
  pcc,
  causalGraph,
  constellation,
  ledger,
  quorum,
  persistence,
  network,
  hybridCrypto,
  hybridTransferAuthorization,
  hybridQuorum,
  privacy,
  checkpoint,
  actum,
  optimizer,

  ...constants,
  ...errors,

  PrincipleRecord: principle.PrincipleRecord,
  LegacyPrincipleRecord: principle.LegacyPrincipleRecord,
  createPrinciple: principle.createPrinciple,
  decodePrinciple: principle.decodePrinciple,
  decodeLegacyPrinciple: principle.decodeLegacyPrinciple,
  verifyPrinciple: principle.verifyPrinciple,
  verifyLegacyPrinciple: principle.verifyLegacyPrinciple,
  computePrincipleTransitionTrace: principle.computePrincipleTransitionTrace,

  TransferEvent: event.TransferEvent,
  createTransfer: event.createTransfer,
  createEvent: event.createEvent,
  decodeEvent: event.decodeEvent,
  normalizeAct: event.normalizeAct,
  verifyAct: event.verifyAct,

  GlobalState: state.GlobalState,
  normalizeState: state.normalizeState,
  cloneState: state.cloneState,
  computeStateRoot: state.computeStateRoot,
  computeLegacyStateRoot: state.computeLegacyStateRoot,
  applyTransfer: state.applyTransfer,
  applyAct: state.applyAct,
  applyConstellation: state.applyConstellation,
  constellationTransitionTrace: state.constellationTransitionTrace,
  verifyInclusionProof: state.verifyInclusionProof,
  verifyAbsenceProof: state.verifyAbsenceProof,
  verifyStateProof: state.verifyStateProof,

  CoherenceWitness: pcc.CoherenceWitness,
  LegacyCoherenceWitness: pcc.LegacyCoherenceWitness,
  createPcc: pcc.createPcc,
  verifyPcc: pcc.verifyPcc,
  verifyPccTransition: pcc.verifyPccTransition,

  CausalGraph: causalGraph.CausalGraph,
  computeActId: causalGraph.computeActId,
  computeNexoId: causalGraph.computeNexoId,
  ConstellationSelector: constellation.ConstellationSelector,
  selectConstellation: constellation.selectConstellation,
  computeConstellationId: constellation.computeConstellationId,

  VlockLedger: ledger.VlockLedger,
  PermissionedQuorum: quorum.PermissionedQuorum,
  WalStore: persistence.WalStore,
  SnapshotStore: persistence.SnapshotStore,
  recoverWal: persistence.recoverWal,
  recoverAbandonedWriterLock: persistence.recoverAbandonedWriterLock,
  readSnapshot: persistence.readSnapshot,
  writeSnapshotAtomic: persistence.writeSnapshotAtomic,

  EnvelopeVerifier: network.EnvelopeVerifier,
  NonceReplayWindow: network.NonceReplayWindow,
  NonceCounter: network.NonceCounter,
  createEnvelope: network.createEnvelope,
  encodeEnvelope: network.encodeEnvelope,
  decodeEnvelope: network.decodeEnvelope,

  HybridIdentity: hybridCrypto.HybridIdentity,
  verifyHybridSignature: hybridCrypto.verifyHybridSignature,
  createHybridTransferAuthorization: hybridTransferAuthorization.createHybridTransferAuthorization,
  verifyHybridTransferAuthorization: hybridTransferAuthorization.verifyHybridTransferAuthorization,
  nativeHybridSelfTest: hybridCrypto.nativeHybridSelfTest,
  HybridPermissionedQuorum: hybridQuorum.HybridPermissionedQuorum,
  assertPublicLedgerSafe: privacy.assertPublicLedgerSafe,
  createPrivatePayloadCommitment: privacy.createPrivatePayloadCommitment,
  verifyPrivatePayloadCommitment: privacy.verifyPrivatePayloadCommitment,
  computePrivacyRoot: privacy.computePrivacyRoot,
  createCheckpoint: checkpoint.createCheckpoint,
  verifyCheckpoint: checkpoint.verifyCheckpoint,
  createCheckpointFromClosure: checkpoint.createCheckpointFromClosure,
  signCheckpoint: checkpoint.signCheckpoint,
  verifySignedCheckpoint: checkpoint.verifySignedCheckpoint,
  createAnchorIntent: checkpoint.createAnchorIntent,
  verifyAnchorIntent: checkpoint.verifyAnchorIntent,

  ActumMachine: actum.ActumMachine,
  encodeActum: actum.encodeActum,
  decodeActum: actum.decodeActum,
  encodeActumFrame: actum.encodeActumFrame,
  decodeActumFrame: actum.decodeActumFrame,

  OliveiraOptimizer: optimizer.OliveiraOptimizer,
  buildOptimizationPlan: optimizer.buildOptimizationPlan,
  verifyOptimizationPlan: optimizer.verifyOptimizationPlan,
});
