'use strict';
const el = id => document.getElementById(id);
const token = document.querySelector('meta[name="konaet-token"]').content;
const initial = { 'transfer.amountAtomic': '7', 'transfer.nonce': '1', 'transfer.networkId': '28673', 'transfer.previousRoot': 'a'.repeat(64), 'state.senderBalance': '100', 'state.nextNonce': '1', 'state.networkId': '28673', 'state.root': 'a'.repeat(64) };
const errors = { KO_RULE_REJECTED: 'A política .ko rejeitou a entrada.', INVALID_AMOUNT: 'Informe um valor positivo com até 9 casas decimais.', INSUFFICIENT_BALANCE: 'Saldo insuficiente.', TRANSFER_IN_PROGRESS: 'Aguarde a transferência anterior.',
  KO_DEPLOYER_NOT_AUTHORIZED: 'Esta conta não tem permissão para implantar contratos nesta rede.', KO_DEPLOYER_QUOTA_EXHAUSTED: 'Esta conta atingiu sua cota de contratos nesta rede.' };
let timer;
let programExamples = {}, programReceipt, programAccounts = [], programBusy = false;
async function post(url, body) { const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Konaet-Token': token }, body: JSON.stringify(body) }); const result = await response.json(); if (!response.ok) throw Error(errors[result.code] || result.code || 'Falha na execução.'); return result; }
function text(tag, value, className) { const node = document.createElement(tag); node.textContent = value; if (className) node.className = className; return node; }
function amount(value) { const n = BigInt(value), whole = n / 1000000000n, fraction = (n % 1000000000n).toString().padStart(9, '0').replace(/0+$/, ''); return whole.toLocaleString('pt-BR') + (fraction ? ',' + fraction : ''); }
async function refresh() {
  try {
    const response = await fetch('/api/network'); if (!response.ok) throw Error(); const data = await response.json();
    programAccounts = data.accounts;
    const previousContract = el('program-contract').value;
    el('program-contract').replaceChildren(...(data.contracts.length ? data.contracts.map(contract => {
      const option = text('option', `${contract.name} · revisão ${contract.revision} · ${contract.contractId.slice(0, 10)}`); option.value = contract.contractId; return option;
    }) : [text('option', 'Implante um contrato')]));
    if (!data.contracts.length) el('program-contract').firstChild.value = '';
    if (data.contracts.some(contract => contract.contractId === previousContract)) el('program-contract').value = previousContract;
    el('program-call').disabled = programBusy || !data.contracts.length; el('program-read').disabled = programBusy || !data.contracts.length;
    el('connection').textContent = data.converged ? 'Quatro validadores conectados · raízes sincronizadas' : 'Validadores sincronizando';
    el('sequence').textContent = data.sequence; el('quorum').textContent = `${data.threshold} de 4`; el('converged').textContent = data.converged ? '4 / 4' : 'Sincronizando'; el('root').textContent = data.root;
    el('accounts').replaceChildren(...data.accounts.map(account => { const node = text('div', '', 'account'); node.append(text('strong', account.name === 'alice' ? 'Alice' : 'Bob'), text('span', `${amount(account.balanceAtomic)} SND`), text('code', account.address)); return node; }));
    el('validators').replaceChildren(...data.validators.map(v => { const node = text('div', '', 'validator'); node.append(text('strong', v.validatorId), text('p', `Processo ${v.pid} · ${v.peers} peers`), text('p', `Fechamento ${v.sequence}`), text('p', v.policyEnforced ? '✓ .ko aplicado' : '.ko indisponível', v.policyEnforced ? 'good' : '')); return node; }));
    if (data.history.length) el('history').replaceChildren(...data.history.slice().reverse().map(tx => { const node = text('div', '', 'history-item'); node.append(text('strong', `${tx.from} → ${tx.to} · ${amount(tx.amountAtomic)} SND`), text('small', `Confirmada · #${tx.sequence}`), text('code', tx.transactionId)); return node; }));
  } catch { el('connection').textContent = 'Conexão indisponível. Confira se o console continua aberto.'; }
}
el('transfer').addEventListener('submit', async event => { event.preventDefault(); el('send').disabled = true; el('transfer-result').textContent = 'Assinando e aguardando os quatro validadores…'; try { const result = await post('/api/transfer', { from: el('from').value, amount: el('amount').value }); el('transfer-result').textContent = `Transferência confirmada no fechamento ${result.receipt.sequence} · ${result.receipt.elapsedMs} ms`; await refresh(); } catch (error) { el('transfer-result').textContent = error.message; } finally { el('send').disabled = false; } });
el('execute').addEventListener('click', async () => { el('execute').disabled = true; try { const result = await post('/api/ko', { source: el('source').value, phase: el('phase').value, context: JSON.parse(el('context').value) }); el('policy-result').textContent = `Política aprovada · ${result.rulesExecuted} regras executadas\n\nHash: ${result.programSha256}`; } catch (error) { el('policy-result').textContent = error.message; } finally { el('execute').disabled = false; } });
el('phase').addEventListener('change', () => { el('context').value = JSON.stringify(el('phase').value === 'closure' ? { 'closure.actCount': '1', 'closure.byteLength': '400' } : initial, null, 2); });
el('refresh').addEventListener('click', refresh);
el('shutdown').addEventListener('click', async () => { el('shutdown').disabled = true; try { await post('/api/shutdown', {}); clearInterval(timer); el('connection').textContent = 'Console encerrado. Abra Iniciar-Konaet.bat para recuperar esta rede.'; } catch (error) { el('connection').textContent = error.message; el('shutdown').disabled = false; } });
el('context').value = JSON.stringify(initial, null, 2);
fetch('/api/runtime').then(r => r.json()).then(runtime => { el('source').value = runtime.source; }).catch(() => { el('policy-result').textContent = 'Não foi possível carregar o fonte .ko.'; });
void refresh(); timer = setInterval(refresh, 3000);
async function programAction(fn) {
  if (programBusy) return; programBusy = true; el('program-deploy').disabled = true; el('program-call').disabled = true;
  el('program-result').textContent = 'Assinando e aguardando o quórum dos validadores…';
  try { await fn(); } catch (error) { el('program-result').textContent = error.message; }
  finally { programBusy = false; el('program-deploy').disabled = false; await refresh(); }
}
function programResult(result) {
  programReceipt = result.receipt.bundle; el('program-download').disabled = false;
  el('program-result').textContent = `Finalizado no fechamento ${result.receipt.sequence} · ${programReceipt.certificate.signatures.length} assinaturas de validadores.`;
  el('program-output').textContent = JSON.stringify({ contractId: result.receipt.contractId, root: result.receipt.root,
    receipts: programReceipt.afterState.receipts, contractsRoot: programReceipt.afterState.contractsRoot }, null, 2);
}
el('program-example').addEventListener('change', () => { el('program-source').value = programExamples[el('program-example').value] || '';
  const registry = el('program-example').value === 'RegistryToken'; el('program-method').value = registry ? 'mint' : 'increment';
  el('program-args').value = JSON.stringify(registry ? [programAccounts[0]?.address || '', '100'] : ['7']); });
el('program-deploy').addEventListener('click', () => programAction(async () => {
  const result = await post('/api/contracts/deploy', { from: el('program-from').value, source: el('program-source').value.replace(/\r\n/g, '\n'), salt: String(Date.now()), gasLimit: 10000 });
  await refresh(); el('program-contract').value = result.receipt.contractId; programResult(result);
}));
el('program-call').addEventListener('click', () => programAction(async () => {
  const result = await post('/api/contracts/call', { from: el('program-from').value, contractId: el('program-contract').value,
    method: el('program-method').value, args: JSON.parse(el('program-args').value), gasLimit: 10000 }); programResult(result);
}));
el('program-read').addEventListener('click', async () => {
  try { const response = await fetch('/api/contracts/' + el('program-contract').value); if (!response.ok) throw Error('CONTRACT_NOT_FOUND');
    el('program-output').textContent = JSON.stringify((await response.json()).state, null, 2); }
  catch (error) { el('program-result').textContent = error.message; }
});
el('program-download').addEventListener('click', () => {
  if (!programReceipt) return; const url = URL.createObjectURL(new Blob([JSON.stringify(programReceipt, null, 2) + '\n'], { type: 'application/json' }));
  const anchor = document.createElement('a'); anchor.href = url; anchor.download = 'konaet-contrato-recibo.json'; anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
});
fetch('/api/program').then(response => response.json()).then(data => { programExamples = data.examples; el('program-source').value = programExamples.Counter; })
  .catch(() => { el('program-result').textContent = 'Não foi possível carregar os exemplos de contrato.'; });
