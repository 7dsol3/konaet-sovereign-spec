'use strict';
// Adapter keeps the executable language shared by tooling and consensus.
module.exports = Object.freeze({
  runtime: require('../../ko-program/runtime'),
  auth: require('../../ko-program/auth'),
  messages: require('../../ko-program/messages'),
});
