import { generateIdentity, compileContract, signDeployment, signCall, deploySignedContract, callSignedContract } from './program-auth.mjs';
const $ = selector => document.querySelector(selector);
let artifact, state, identities, deployment, busy = false;
let history = [];
function show(title, message, receipt, failed = false) {
  $('#result-title').textContent = title; $('#message').textContent = message;
  $('.receipt-panel').dataset.state = failed ? 'error' : 'ok';
  if (receipt) {
    $('#receipt').textContent = JSON.stringify(receipt, null, 2);
    $('#gas-used').textContent = receipt.gasUsed ?? '—';
    $('#verified').textContent = receipt.signatureVerified ? 'Verificada' : '—';
  }
  $('#revision').textContent = state?.revision ?? '—';
}
function enabled() {
  $('#deploy').disabled = busy; $('#example').disabled = busy;
  for (const id of ['execute', 'method', 'args', 'signer', 'download']) $('#' + id).disabled = busy || !state;
  $('#gas').disabled = busy;
}
async function action(fn) {
  if (busy) return; busy = true; enabled();
  try { await fn(); } catch (error) {
    show('Chamada rejeitada', (error.code || 'ERRO') + ': ' + error.message + (state ? ' · Estado preservado na revisão ' + state.revision + '.' : ''),
      { accepted: false, code: error.code || 'ERRO', state: state ?? null }, true);
  } finally { busy = false; enabled(); }
}
async function example() {
  const response = await fetch('examples/' + $('#example').value + '.ko');
  if (!response.ok) throw Error('Não foi possível carregar o exemplo.');
  $('#source').value = await response.text();
}
function signer() { return identities[$('#signer').value]; }
function address() { if (identities) $('#address').textContent = signer().address; }
function args() {
  if (!artifact) return;
  const fn = artifact.program.functions.find(item => item.name === $('#method').value);
  $('#args').value = JSON.stringify(fn.args.map(arg => arg.type === 'bool' ? false : arg.type === 'address'
    ? (fn.name === 'mint' || fn.name === 'balanceOf' ? signer().address : identities.visitor.address) : fn.name === 'mint' ? '100' : '7'));
}
$('#example').addEventListener('change', () => action(example));
$('#method').addEventListener('change', args);
$('#signer').addEventListener('change', () => { address(); args(); });
$('#deploy').addEventListener('click', () => action(async () => {
  const compiled = compileContract($('#source').value.replace(/\r\n/g, '\n'));
  const owner = await generateIdentity(), visitor = await generateIdentity();
  const packet = await signDeployment(compiled, { networkId: '77', salt: '0', gasLimit: 10000 }, owner);
  const receipt = await deploySignedContract(compiled, packet);
  artifact = compiled; state = receipt.state; identities = { owner, visitor }; deployment = packet; history = [];
  $('#signer').value = 'owner'; $('#method').replaceChildren(...artifact.program.functions.filter(fn => !fn.internal).map(fn => {
    const option = document.createElement('option'); option.value = fn.name; option.textContent = fn.name + (fn.view ? ' · consulta' : ''); return option;
  }));
  address(); args(); $('#badge').textContent = artifact.program.contract + ' · ativo'; $('#badge').classList.add('ready');
  show('Contrato criado', 'Fonte compilado. Dono derivado da chave pública. Nova instância na rede de sessão 77.', receipt);
}));
$('#execute').addEventListener('click', () => action(async () => {
  if (!state || history.length >= 100) throw Error('Baixe os recibos e crie uma nova sessão. Limite: 100 chamadas.');
  const gasLimit = Number($('#gas').value);
  if (!Number.isSafeInteger(gasLimit) || gasLimit < 1 || gasLimit > 100000) throw Error('Use um limite inteiro entre 1 e 100000.');
  const request = { method: $('#method').value, args: JSON.parse($('#args').value), gasLimit };
  const packet = await signCall(artifact, state, request, signer());
  const receipt = await callSignedContract(artifact, state, packet);
  state = receipt.state; history.push({ envelope: packet, receipt });
  show(receipt.readOnly ? 'Consulta executada' : 'Estado atualizado', 'Assinatura verificada · ' + receipt.method + ' → ' + JSON.stringify(receipt.result) + ' · ' + receipt.events.length + ' evento(s).', receipt);
}));
$('#download').addEventListener('click', () => {
  if (!state) return;
  const bundle = { schema: 'konaet.ko-studio-session.v1', execution: 'browser-session', artifact, deployment, calls: history, state };
  const url = URL.createObjectURL(new Blob([JSON.stringify(bundle, null, 2) + '\n'], { type: 'application/json' }));
  const anchor = document.createElement('a'); anchor.href = url; anchor.download = artifact.program.contract + '-recibos.json'; anchor.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
});
action(example);
