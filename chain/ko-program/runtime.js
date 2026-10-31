'use strict';

const { createHash } = require('node:crypto');
const PROFILE = 'KONAET_KO_PROGRAM_V1';
const SCHEMA = 'konaet.ko-program.v1';
const STATE_SCHEMA = 'konaet.ko-program-state.v1';
const MAX_U128 = (1n << 128n) - 1n;
const MAX_REVISION = (1n << 64n) - 1n;
const TYPES = new Set(['u128', 'bool', 'address']);
const RESERVED = new Set(['caller', 'network', 'true', 'false', 'runtime', 'storage', 'mapping', 'event',
  'fn', 'view', 'internal', 'let', 'set', 'if', 'else', 'repeat', 'require', 'emit', 'return', 'end', 'contract',
  'u128', 'bool', 'address', 'void', ...Object.getOwnPropertyNames(Object.prototype)]);
const compiled = new WeakSet();

class KoProgramError extends Error {
  constructor(code, message) { super(message); this.name = 'KoProgramError'; this.code = code; }
}
function fail(code, message) { throw new KoProgramError(code, message); }
function need(condition, code, message) { if (!condition) fail(code, message); }
function hash(value) { return createHash('sha256').update(typeof value === 'string' ? value : JSON.stringify(value)).digest('hex'); }
function freeze(value) { if (value && typeof value === 'object') { Object.values(value).forEach(freeze); Object.freeze(value); } return value; }
function plain(value, budget = { nodes: 0 }, depth = 0) {
  need(++budget.nodes <= 65536 && depth <= 60, 'KO_DATA_LIMIT', 'Data structure exceeds limits.');
  if (value === null || typeof value === 'boolean') return value;
  if (typeof value === 'string') { need(value.length <= 131072, 'KO_DATA_LIMIT', 'String exceeds limit.'); return value; }
  if (typeof value === 'number') { need(Number.isSafeInteger(value), 'KO_DATA_INVALID', 'Safe integer required.'); return value; }
  need(value && typeof value === 'object' && (Array.isArray(value)
    || Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null), 'KO_DATA_INVALID', 'Plain JSON data required.');
  need(Object.getOwnPropertySymbols(value).length === 0, 'KO_DATA_INVALID', 'Symbol properties are not supported.');
  const output = Array.isArray(value) ? [] : {};
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const [key, descriptor] of Object.entries(descriptors)) {
    if (Array.isArray(value) && key === 'length') continue;
    need(descriptor.enumerable && Object.hasOwn(descriptor, 'value') && key !== '__proto__', 'KO_DATA_INVALID', 'Accessors and hidden data are not supported.');
    if (Array.isArray(value)) need(/^(0|[1-9][0-9]*)$/.test(key) && Number(key) < value.length, 'KO_DATA_INVALID', 'Dense array required.');
    Object.defineProperty(output, key, { value: plain(descriptor.value, budget, depth + 1), writable: true, enumerable: true, configurable: true });
  }
  if (Array.isArray(value)) need(output.length === value.length && Object.keys(output).length === value.length, 'KO_DATA_INVALID', 'Dense array required.');
  return output;
}
function keys(value, expected, code = 'KO_STATE_INVALID') {
  need(value && !Array.isArray(value) && typeof value === 'object'
    && JSON.stringify(Object.keys(value).sort()) === JSON.stringify([...expected].sort()), code, 'Unexpected or missing fields.');
}
function uint(value, maximum = MAX_U128) {
  need(typeof value === 'string' && /^(0|[1-9][0-9]{0,38})$/.test(value), 'KO_VALUE_INVALID', 'Unsigned quantities must be canonical decimal strings.');
  const result = BigInt(value); need(result <= maximum, 'KO_OVERFLOW', 'Unsigned integer exceeds its bound.'); return result;
}
function address(value) { need(typeof value === 'string' && /^v7[a-z2-7]{32}$/.test(value), 'KO_ADDRESS_INVALID', 'Canonical Konaet v7 address required.'); return value; }
function typed(value, type) {
  if (type === 'u128') return uint(value);
  if (type === 'address') return address(value);
  need(type === 'bool' && typeof value === 'boolean', 'KO_TYPE_ERROR', 'Boolean value required.'); return value;
}
function encode(value) { return typeof value === 'bigint' ? value.toString() : value; }
function defaultValue(type) { return type === 'u128' ? 0n : type === 'bool' ? false : 'v7' + 'a'.repeat(32); }

function tokenize(source) {
  need(typeof source === 'string' && source.length > 0 && Buffer.byteLength(source) <= 65536
    && !source.includes('\r') && !/[^\t\n -~]/.test(source), 'KO_SOURCE_INVALID', 'Source must be ASCII, LF and at most 64 KiB.');
  const tokens = []; let cursor = 0;
  while (cursor < source.length) {
    const rest = source.slice(cursor), first = rest[0];
    if (/\s/.test(first)) { cursor++; continue; }
    if (first === '#') { const end = source.indexOf('\n', cursor); cursor = end < 0 ? source.length : end + 1; continue; }
    const match = rest.match(/^(?:[A-Za-z_][A-Za-z0-9_]*|0|[1-9][0-9]*|"v7[a-z2-7]{32}"|->|=>|==|!=|<=|>=|&&|\|\||[{}()[\]:;,=+*/%!<>-])/);
    need(match && match[0].length <= 80, 'KO_SYNTAX_ERROR', `Invalid token at offset ${cursor}.`);
    tokens.push(match[0]); cursor += match[0].length;
    need(tokens.length <= 8192, 'KO_SOURCE_LIMIT', 'Too many source tokens.');
  }
  tokens.push('<eof>'); return tokens;
}
function parse(source) {
  const tokens = tokenize(source); let offset = 0, nodes = 0;
  const peek = () => tokens[offset];
  const take = value => { const token = tokens[offset++]; need(value === undefined || token === value, 'KO_SYNTAX_ERROR', `Expected ${value}, found ${token}.`); return token; };
  const maybe = value => peek() === value ? (take(), true) : false;
  const name = () => { const value = take(); need(/^[A-Za-z][A-Za-z0-9_]{0,47}$/.test(value) && !RESERVED.has(value), 'KO_NAME_INVALID', `Invalid name ${value}.`); return value; };
  const type = (allowVoid = false) => { const value = take(); need(TYPES.has(value) || (allowVoid && value === 'void'), 'KO_TYPE_ERROR', 'Unknown type.'); return value; };
  const node = (value, children = []) => {
    const depth = 1 + Math.max(0, ...children.filter(Boolean).map(item => item.depth));
    need(++nodes <= 4096 && depth <= 48, 'KO_SOURCE_LIMIT', 'Program or expression exceeds limits.');
    return { ...value, depth };
  };
  const precedence = { '||': 1, '&&': 2, '==': 3, '!=': 3, '<': 4, '>': 4, '<=': 4, '>=': 4, '+': 5, '-': 5, '*': 6, '/': 6, '%': 6 };
  function expression(minimum = 0, nesting = 0) {
    need(nesting <= 40, 'KO_SOURCE_LIMIT', 'Expression nesting exceeds limit.');
    let left;
    if (maybe('!')) { const item = expression(7, nesting + 1); left = node({ kind: 'not', value: item }, [item]); }
    else if (maybe('(')) { left = expression(0, nesting + 1); take(')'); }
    else if (/^(0|[1-9][0-9]*)$/.test(peek())) { const value = take(); uint(value); left = node({ kind: 'literal', type: 'u128', value }); }
    else if (peek() === 'true' || peek() === 'false') left = node({ kind: 'literal', type: 'bool', value: take() === 'true' });
    else if (peek().startsWith('"')) left = node({ kind: 'literal', type: 'address', value: take().slice(1, -1) });
    else {
      const identifier = take();
      need(/^[A-Za-z][A-Za-z0-9_]{0,47}$/.test(identifier), 'KO_SYNTAX_ERROR', 'Expression expected.');
      if (maybe('[')) { const key = expression(0, nesting + 1); take(']'); left = node({ kind: 'map', name: identifier, key }, [key]); }
      else if (maybe('(')) {
        const args = [];
        if (peek() !== ')') { do { args.push(expression(0, nesting + 1)); need(args.length <= 16, 'KO_SOURCE_LIMIT', 'Too many arguments.'); } while (maybe(',')); }
        take(')'); left = node({ kind: 'call', name: identifier, args }, args);
      } else left = node({ kind: 'name', name: identifier });
    }
    while (Object.hasOwn(precedence, peek()) && precedence[peek()] >= minimum) {
      const operator = take(), right = expression(precedence[operator] + 1, nesting + 1);
      left = node({ kind: 'binary', operator, left, right }, [left, right]);
    }
    return left;
  }
  function argumentsDefinition() {
    take('('); const args = [];
    if (peek() !== ')') { do { const id = name(); take(':'); args.push({ name: id, type: type() }); need(args.length <= 16, 'KO_SOURCE_LIMIT', 'Too many parameters.'); } while (maybe(',')); }
    take(')'); need(new Set(args.map(arg => arg.name)).size === args.length, 'KO_DUPLICATE_NAME', 'Duplicate parameter.'); return args;
  }
  function block(nesting = 0) {
    need(nesting <= 16, 'KO_SOURCE_LIMIT', 'Block nesting exceeds limit.'); take('{'); const statements = [];
    while (peek() !== '}') {
      need(peek() !== '<eof>', 'KO_SYNTAX_ERROR', 'Unclosed block.');
      const kind = take(); let statement;
      if (kind === 'let') { const id = name(); take(':'); const valueType = type(); take('='); const value = expression(); take(';'); statement = { kind, name: id, type: valueType, value }; }
      else if (kind === 'set') {
        const id = name(), key = maybe('[') ? expression() : null; if (key) take(']'); take('='); const value = expression(); take(';'); statement = { kind, name: id, key, value };
      } else if (kind === 'require') { const condition = expression(); take(';'); statement = { kind, condition }; }
      else if (kind === 'return') { const value = peek() === ';' ? null : expression(); take(';'); statement = { kind, value }; }
      else if (kind === 'emit') {
        const id = name(); take('('); const args = [];
        if (peek() !== ')') { do { args.push(expression()); need(args.length <= 16, 'KO_SOURCE_LIMIT', 'Too many event fields.'); } while (maybe(',')); }
        take(')'); take(';'); statement = { kind, name: id, args };
      } else if (kind === 'if') {
        const condition = expression(); const yes = block(nesting + 1), no = maybe('else') ? block(nesting + 1) : [];
        statement = { kind, condition, yes, no };
      } else if (kind === 'repeat') {
        const count = take(); need(/^(0|[1-9][0-9]*)$/.test(count) && BigInt(count) <= 256n, 'KO_LOOP_LIMIT', 'Repeat count must be a constant from 0 to 256.');
        statement = { kind, count: Number(count), body: block(nesting + 1) };
      } else fail('KO_SYNTAX_ERROR', `Unsupported statement ${kind}.`);
      statements.push(statement); need(++nodes <= 4096, 'KO_SOURCE_LIMIT', 'Program exceeds node limit.');
    }
    take('}'); return statements;
  }
  take('contract'); const contract = name(); take('v1'); take('runtime'); take(':'); take(PROFILE);
  const storage = [], mappings = [], events = [], functions = [];
  while (peek() !== 'end') {
    if (maybe('storage')) { const id = name(); take(':'); const valueType = type(); take('='); const initial = expression(); take(';'); storage.push({ name: id, type: valueType, initial }); }
    else if (maybe('mapping')) { const id = name(); take(':'); const keyType = type(); need(keyType !== 'bool', 'KO_TYPE_ERROR', 'Mapping keys must be address or u128.'); take('=>'); const valueType = type(); take(';'); mappings.push({ name: id, keyType, type: valueType }); }
    else if (maybe('event')) { const id = name(), fields = argumentsDefinition(); take(';'); events.push({ name: id, fields }); }
    else {
      const internal = maybe('internal'), view = maybe('view'); take('fn'); const id = name(), args = argumentsDefinition(); take('->'); const returns = type(true);
      functions.push({ name: id, internal, view, args, returns, body: block() });
    }
    need(storage.length <= 32 && mappings.length <= 16 && events.length <= 32 && functions.length <= 32, 'KO_SOURCE_LIMIT', 'Too many declarations.');
  }
  take('end'); take('<eof>'); need(functions.some(fn => !fn.internal), 'KO_PROGRAM_EMPTY', 'A public function is required.');
  return { profile: PROFILE, contract, version: '1', storage, mappings, events, functions };
}

function check(program) {
  const storage = new Map(program.storage.map(item => [item.name, item]));
  const mappings = new Map(program.mappings.map(item => [item.name, item]));
  const events = new Map(program.events.map(item => [item.name, item]));
  const functions = new Map(program.functions.map(item => [item.name, item]));
  const all = [...program.storage, ...program.mappings, ...program.events, ...program.functions];
  need(new Set(all.map(item => item.name)).size === all.length, 'KO_DUPLICATE_NAME', 'Declaration names must be distinct.');
  const effects = new Map(), calls = new Map();
  function expr(item, locals, current = null, initial = false) {
    if (item.kind === 'literal') return item.type;
    if (item.kind === 'name') {
      if (item.name === 'caller') return 'address'; if (item.name === 'network') return 'u128';
      if (locals.has(item.name)) return locals.get(item.name);
      need(!initial && storage.has(item.name), 'KO_UNKNOWN_NAME', `Unknown value ${item.name}.`); return storage.get(item.name).type;
    }
    if (item.kind === 'map') {
      need(!initial && mappings.has(item.name), 'KO_UNKNOWN_NAME', `Unknown mapping ${item.name}.`);
      const map = mappings.get(item.name); need(expr(item.key, locals, current, initial) === map.keyType, 'KO_TYPE_ERROR', 'Mapping key type mismatch.'); return map.type;
    }
    if (item.kind === 'call') {
      need(!initial && functions.has(item.name), 'KO_UNKNOWN_FUNCTION', `Unknown function ${item.name}.`);
      const fn = functions.get(item.name); need(fn.returns !== 'void', 'KO_TYPE_ERROR', 'Void function cannot be an expression.');
      need(fn.args.length === item.args.length, 'KO_ARGUMENTS_INVALID', 'Argument count mismatch.');
      item.args.forEach((value, index) => need(expr(value, locals, current, initial) === fn.args[index].type, 'KO_TYPE_ERROR', 'Argument type mismatch.'));
      calls.get(current).add(item.name); return fn.returns;
    }
    if (item.kind === 'not') { need(expr(item.value, locals, current, initial) === 'bool', 'KO_TYPE_ERROR', 'Boolean operand required.'); return 'bool'; }
    const left = expr(item.left, locals, current, initial), right = expr(item.right, locals, current, initial);
    need(left === right, 'KO_TYPE_ERROR', 'Operand types differ.');
    if (['&&', '||'].includes(item.operator)) { need(left === 'bool', 'KO_TYPE_ERROR', 'Boolean operands required.'); return 'bool'; }
    if (['==', '!='].includes(item.operator)) return 'bool';
    need(left === 'u128', 'KO_TYPE_ERROR', 'Unsigned integer operands required.');
    return ['<', '<=', '>', '>='].includes(item.operator) ? 'bool' : 'u128';
  }
  for (const field of program.storage) need(expr(field.initial, new Map(), null, true) === field.type, 'KO_TYPE_ERROR', 'Initializer type mismatch.');
  function block(statements, locals, fn) {
    for (const statement of statements) {
      if (statement.kind === 'let') {
        need(!locals.has(statement.name) && !all.some(item => item.name === statement.name), 'KO_DUPLICATE_NAME', 'Local name shadows another declaration.');
        need(expr(statement.value, locals, fn.name) === statement.type, 'KO_TYPE_ERROR', 'Local type mismatch.'); locals.set(statement.name, statement.type);
      } else if (statement.kind === 'set') {
        const target = statement.key ? mappings.get(statement.name) : storage.get(statement.name);
        need(target, 'KO_STORAGE_INVALID', 'Only declared storage and mappings can be assigned.');
        if (statement.key) need(expr(statement.key, locals, fn.name) === target.keyType, 'KO_TYPE_ERROR', 'Mapping key type mismatch.');
        need(expr(statement.value, locals, fn.name) === target.type, 'KO_TYPE_ERROR', 'Storage type mismatch.'); effects.set(fn.name, true);
      } else if (statement.kind === 'require' || statement.kind === 'if') {
        need(expr(statement.condition, locals, fn.name) === 'bool', 'KO_TYPE_ERROR', 'Boolean condition required.');
        if (statement.kind === 'if') { block(statement.yes, new Map(locals), fn); block(statement.no, new Map(locals), fn); }
      } else if (statement.kind === 'repeat') block(statement.body, new Map(locals), fn);
      else if (statement.kind === 'emit') {
        const event = events.get(statement.name); need(event && event.fields.length === statement.args.length, 'KO_EVENT_INVALID', 'Unknown event or invalid field count.');
        statement.args.forEach((value, index) => need(expr(value, locals, fn.name) === event.fields[index].type, 'KO_TYPE_ERROR', 'Event field type mismatch.')); effects.set(fn.name, true);
      } else if (statement.kind === 'return') {
        const result = statement.value ? expr(statement.value, locals, fn.name) : 'void'; need(result === fn.returns, 'KO_TYPE_ERROR', 'Return type mismatch.');
      }
    }
  }
  for (const fn of program.functions) { calls.set(fn.name, new Set()); effects.set(fn.name, false); }
  for (const fn of program.functions) {
    need(fn.args.every(arg => !all.some(item => item.name === arg.name)), 'KO_DUPLICATE_NAME', 'Parameter shadows a declaration.');
    block(fn.body, new Map(fn.args.map(arg => [arg.name, arg.type])), fn);
    if (fn.returns !== 'void') need(fn.body.at(-1)?.kind === 'return', 'KO_RETURN_REQUIRED', 'Value functions must end with return.');
  }
  const visiting = new Set(), done = new Set();
  function visit(name) {
    need(!visiting.has(name), 'KO_RECURSION_FORBIDDEN', 'Recursive call graphs are not supported.');
    if (done.has(name)) return effects.get(name);
    visiting.add(name); for (const called of calls.get(name)) if (visit(called)) effects.set(name, true);
    visiting.delete(name); done.add(name); return effects.get(name);
  }
  for (const fn of program.functions) { const writes = visit(fn.name); need(!fn.view || !writes, 'KO_VIEW_EFFECT', 'View functions cannot write storage or emit, including through calls.'); }
  return program;
}

function compileContract(source) {
  const program = check(parse(source));
  const artifact = freeze({ schema: SCHEMA, profile: PROFILE, source, sourceSha256: hash(source), programSha256: hash(program), program });
  compiled.add(artifact); return artifact;
}
function validateContract(input) {
  const artifact = plain(input); keys(artifact, ['schema', 'profile', 'source', 'sourceSha256', 'programSha256', 'program'], 'KO_ARTIFACT_INVALID');
  const expected = compileContract(artifact.source);
  need(JSON.stringify(artifact) === JSON.stringify(expected), 'KO_ARTIFACT_MISMATCH', 'Source, program and hashes differ.'); return expected;
}
function policy(input) { return compiled.has(input) ? input : validateContract(input); }
function seal(fields) { return freeze({ ...fields, stateRoot: hash(fields) }); }
function validateState(artifact, input) {
  const state = plain(input); keys(state, ['schema', 'programSha256', 'contractId', 'networkId', 'deployer', 'salt', 'revision', 'storage', 'mappings', 'stateRoot']);
  need(state.schema === STATE_SCHEMA && state.programSha256 === artifact.programSha256, 'KO_STATE_PROFILE', 'State belongs to another program.');
  address(state.deployer); const network = uint(state.networkId, 0xffffffffn); need(network > 0n, 'KO_NETWORK_INVALID', 'Network id must be positive.'); uint(state.salt); uint(state.revision, MAX_REVISION);
  need(state.contractId === hash({ programSha256: artifact.programSha256, networkId: state.networkId, deployer: state.deployer, salt: state.salt }), 'KO_CONTRACT_ID_MISMATCH', 'Contract identity mismatch.');
  keys(state.storage, artifact.program.storage.map(item => item.name)); keys(state.mappings, artifact.program.mappings.map(item => item.name));
  for (const field of artifact.program.storage) typed(state.storage[field.name], field.type);
  let entries = 0;
  for (const map of artifact.program.mappings) {
    const rows = state.mappings[map.name]; need(Array.isArray(rows), 'KO_STATE_INVALID', 'Mapping rows must be an array.'); let previous = null;
    for (const row of rows) {
      keys(row, ['key', 'value']); const key = encode(typed(row.key, map.keyType)); typed(row.value, map.type);
      need(previous === null || previous < key, 'KO_STATE_ORDER', 'Mapping keys must be unique and bytewise sorted.'); previous = key;
      need(++entries <= 4096, 'KO_STORAGE_LIMIT', 'Mapping entry limit exceeded.');
    }
  }
  const fields = { schema: STATE_SCHEMA, programSha256: artifact.programSha256, contractId: state.contractId,
    networkId: state.networkId, deployer: state.deployer, salt: state.salt, revision: state.revision,
    storage: Object.fromEntries(artifact.program.storage.map(field => [field.name, state.storage[field.name]])),
    mappings: Object.fromEntries(artifact.program.mappings.map(field => [field.name, state.mappings[field.name].map(row => ({ key: row.key, value: row.value }))])) };
  need(state.stateRoot === hash(fields), 'KO_STATE_ROOT_MISMATCH', 'State root does not match its contents.');
  return fields;
}

function machine(artifact, fields, caller, gasLimit = 10000) {
  need(Number.isSafeInteger(gasLimit) && gasLimit >= 1 && gasLimit <= 1000000, 'KO_GAS_INVALID', 'Gas limit must be from 1 to 1000000.');
  const program = artifact.program, storage = new Map(program.storage.map(field => [field.name, typed(fields.storage[field.name], field.type)]));
  const maps = new Map(program.mappings.map(field => [field.name, new Map(fields.mappings[field.name].map(row => [row.key, typed(row.value, field.type)]))]));
  const mapDefinitions = new Map(program.mappings.map(field => [field.name, field])), functions = new Map(program.functions.map(fn => [fn.name, fn]));
  const events = []; let gasUsed = 0, callDepth = 0;
  function charge(amount = 1) { gasUsed += amount; need(gasUsed <= gasLimit, 'KO_OUT_OF_GAS', 'Execution exceeded gas budget.'); }
  function evalExpr(item, locals) {
    charge();
    if (item.kind === 'literal') return typed(item.value, item.type);
    if (item.kind === 'name') { if (item.name === 'caller') return caller; if (item.name === 'network') return BigInt(fields.networkId); return locals.has(item.name) ? locals.get(item.name) : storage.get(item.name); }
    if (item.kind === 'map') { charge(4); const key = encode(evalExpr(item.key, locals)); return maps.get(item.name).get(key) ?? defaultValue(mapDefinitions.get(item.name).type); }
    if (item.kind === 'call') return invoke(functions.get(item.name), item.args.map(arg => evalExpr(arg, locals)));
    if (item.kind === 'not') return !evalExpr(item.value, locals);
    const left = evalExpr(item.left, locals);
    if (item.operator === '&&') return left && evalExpr(item.right, locals);
    if (item.operator === '||') return left || evalExpr(item.right, locals);
    const right = evalExpr(item.right, locals);
    if (item.operator === '==') return left === right; if (item.operator === '!=') return left !== right;
    if (item.operator === '<') return left < right; if (item.operator === '>') return left > right;
    if (item.operator === '<=') return left <= right; if (item.operator === '>=') return left >= right;
    if (item.operator === '/' || item.operator === '%') need(right !== 0n, 'KO_DIVISION_BY_ZERO', 'Division by zero.');
    const value = item.operator === '+' ? left + right : item.operator === '-' ? left - right : item.operator === '*' ? left * right : item.operator === '/' ? left / right : left % right;
    need(value >= 0n && value <= MAX_U128, value < 0n ? 'KO_UNDERFLOW' : 'KO_OVERFLOW', 'Arithmetic result exceeds uint128.'); return value;
  }
  function block(statements, locals) {
    for (const statement of statements) {
      charge();
      if (statement.kind === 'let') locals.set(statement.name, evalExpr(statement.value, locals));
      else if (statement.kind === 'set') {
        const key = statement.key ? encode(evalExpr(statement.key, locals)) : null, value = evalExpr(statement.value, locals); charge(statement.key ? 20 : 10);
        if (statement.key) {
          const map = maps.get(statement.name); map.set(key, value);
          need([...maps.values()].reduce((total, entries) => total + entries.size, 0) <= 4096, 'KO_STORAGE_LIMIT', 'Mapping entry limit exceeded.');
        } else storage.set(statement.name, value);
      } else if (statement.kind === 'require') need(evalExpr(statement.condition, locals) === true, 'KO_REQUIRE_FAILED', 'Contract requirement failed.');
      else if (statement.kind === 'return') return { returned: true, value: statement.value ? evalExpr(statement.value, locals) : null };
      else if (statement.kind === 'if') { const result = block(evalExpr(statement.condition, locals) ? statement.yes : statement.no, new Map(locals)); if (result) return result; }
      else if (statement.kind === 'repeat') { for (let index = 0; index < statement.count; index++) { charge(); const result = block(statement.body, new Map(locals)); if (result) return result; } }
      else if (statement.kind === 'emit') {
        charge(10); need(events.length < 128, 'KO_EVENT_LIMIT', 'Too many emitted events.');
        events.push({ name: statement.name, values: statement.args.map(arg => encode(evalExpr(arg, locals))) });
      }
    }
    return null;
  }
  function invoke(fn, args) {
    charge(10); need(++callDepth <= 32, 'KO_CALL_DEPTH', 'Function call depth exceeded.');
    try { return block(fn.body, new Map(fn.args.map((arg, index) => [arg.name, args[index]])))?.value ?? null; } finally { callDepth--; }
  }
  return { evalExpr, invoke, events, get gasUsed() { return gasUsed; }, snapshot() {
    return { storage: Object.fromEntries(program.storage.map(field => [field.name, encode(storage.get(field.name))])),
      mappings: Object.fromEntries(program.mappings.map(field => [field.name, [...maps.get(field.name)].sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, value]) => ({ key, value: encode(value) }))])) };
  } };
}
function deployContract(input, options) {
  const artifact = policy(input), config = plain(options);
  need(config && typeof config === 'object' && !Array.isArray(config), 'KO_CALL_INVALID', 'Deployment options required.');
  need(Object.keys(config).every(key => ['caller', 'networkId', 'salt', 'gasLimit'].includes(key)), 'KO_CALL_INVALID', 'Unexpected deployment option.');
  const caller = address(config.caller), networkId = uint(config.networkId, 0xffffffffn).toString(), salt = uint(config.salt ?? '0').toString();
  need(networkId !== '0', 'KO_NETWORK_INVALID', 'Network id must be positive.');
  const fields = { schema: STATE_SCHEMA, programSha256: artifact.programSha256,
    contractId: hash({ programSha256: artifact.programSha256, networkId, deployer: caller, salt }), networkId, deployer: caller, salt, revision: '0',
    storage: Object.fromEntries(artifact.program.storage.map(field => [field.name, encode(defaultValue(field.type))])),
    mappings: Object.fromEntries(artifact.program.mappings.map(field => [field.name, []])) };
  const vm = machine(artifact, fields, caller, config.gasLimit);
  for (const field of artifact.program.storage) fields.storage[field.name] = encode(vm.evalExpr(field.initial, new Map()));
  return freeze({ state: seal(fields), gasUsed: vm.gasUsed });
}
function callContract(input, stateInput, options) {
  const artifact = policy(input), fields = validateState(artifact, stateInput), call = plain(options);
  need(call && typeof call === 'object' && !Array.isArray(call)
    && Object.keys(call).every(key => ['caller', 'method', 'args', 'expectedRevision', 'gasLimit'].includes(key)), 'KO_CALL_INVALID', 'Invalid call options.');
  const caller = address(call.caller), fn = artifact.program.functions.find(item => item.name === call.method);
  need(fn && !fn.internal, 'KO_ENTRYPOINT_INVALID', 'Public entrypoint required.');
  need(Array.isArray(call.args) && call.args.length === fn.args.length, 'KO_ARGUMENTS_INVALID', 'Argument count mismatch.');
  need(call.expectedRevision === fields.revision, 'KO_STALE_STATE', 'Expected revision does not match current state.');
  const args = call.args.map((value, index) => typed(value, fn.args[index].type));
  const vm = machine(artifact, fields, caller, call.gasLimit), result = vm.invoke(fn, args);
  const nextRevision = BigInt(fields.revision) + (fn.view ? 0n : 1n); need(nextRevision <= MAX_REVISION, 'KO_OVERFLOW', 'State revision overflow.');
  const state = seal({ ...fields, revision: nextRevision.toString(), ...vm.snapshot() });
  return freeze({ accepted: true, profile: PROFILE, method: fn.name, readOnly: fn.view, result: encode(result),
    gasUsed: vm.gasUsed, events: vm.events, previousRoot: stateInput.stateRoot, state });
}

module.exports = Object.freeze({ PROFILE, SCHEMA, STATE_SCHEMA, KoProgramError, compileContract, validateContract, deployContract, callContract });
