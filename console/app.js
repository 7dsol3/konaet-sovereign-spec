'use strict';
const el = id => document.getElementById(id);
const token = document.querySelector('meta[name="konaet-token"]').content;
const initial = { 'transfer.amountAtomic': '7', 'transfer.nonce': '1', 'transfer.networkId': '28673', 'transfer.previousRoot': 'a'.repeat(64), 'state.senderBalance': '100', 'state.nextNonce': '1', 'state.networkId': '28673', 'state.root': 'a'.repeat(64) };
const errors = { KO_RULE_REJECTED: 'A política .ko rejeitou a entrada.', INVALID_AMOUNT: 'Informe um valor positivo com até 9 casas decimais.', INSUFFICIENT_BALANCE: 'Saldo insuficiente.', TRANSFER_IN_PROGRESS: 'Aguarde a transferência anterior.' };
let timer;
async function post(url, body) { const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Konaet-Token': token }, body: JSON.stringify(body) }); const result = await response.json(); if (!response.ok) throw Error(errors[result.code] || result.code || 'Falha na execução.'); return result; }
function text(tag, value, className) { const node = document.createElement(tag); node.textContent = value; if (className) node.className = className; return node; }
function amount(value) { const n = BigInt(value), whole = n / 1000000000n, fraction = (n % 1000000000n).toString().padStart(9, '0').replace(/0+$/, ''); return whole.toLocaleString('pt-BR') + (fraction ? ',' + fraction : ''); }
async function refresh() {
  try {
    const response = await fetch('/api/network'); if (!response.ok) throw Error(); const data = await response.json();
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
