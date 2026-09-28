const state = {
  conversations: [],
  activeConversationId: null,
  activeStream: null,
  lastListenText: ''
};
const $ = selector => document.querySelector(selector);

function createId() {
  if (crypto.randomUUID) return crypto.randomUUID();
  return 'id-' + Math.random().toString(36).slice(2) + Date.now().toString(36);
}

function toast(message, error = false) {
  const item = document.createElement('div');
  item.textContent = message;
  if (error) item.classList.add('error');
  $('#toast').appendChild(item);
  setTimeout(() => item.remove(), 4000);
}

function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, char => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[char]));
}

function renderMarkdown(text) {
  if (window.marked && window.DOMPurify) {
    return DOMPurify.sanitize(marked.parse(text));
  }
  return escapeHtml(text);
}

function setStreamStatus(text, visible = true) {
  $('#streamStatus').classList.toggle('hidden', !visible);
  $('#streamStatusText').innerHTML = `<span class="status-spinner"></span>${escapeHtml(text)}`;
}

function setBusy(busy) {
  $('#sendMessage').disabled = busy;
  $('#chatInput').disabled = busy;
  if (!busy) setStreamStatus('', false);
}

async function request(path, options = {}) {
  const response = await fetch(path, {
    headers: { 'Content-Type': 'application/json' },
    ...options
  });
  const body = response.headers.get('content-type')?.includes('json') ? await response.json() : null;
  if (!response.ok) throw new Error(body?.message || `请求失败 (${response.status})`);
  return body;
}

// ---------- conversations ----------

function newConversation() {
  const conversation = { id: createId(), title: '新对话', messages: [], updatedAt: new Date().toISOString() };
  state.conversations.unshift(conversation);
  state.activeConversationId = conversation.id;
  saveConversations();
  renderConversations();
  renderChatMessages();
}

function saveConversations() {
  localStorage.setItem('dsh.portguard.conversations', JSON.stringify(state.conversations.slice(0, 50)));
}

function loadConversations() {
  try { state.conversations = JSON.parse(localStorage.getItem('dsh.portguard.conversations') || '[]'); }
  catch { state.conversations = []; }
}

function renderConversations() {
  const list = $('#conversationList');
  list.innerHTML = '';
  state.conversations.forEach(conversation => {
    const button = document.createElement('button');
    button.className = 'conv-item' + (conversation.id === state.activeConversationId ? ' active' : '');
    button.textContent = conversation.title;
    button.onclick = () => {
      state.activeConversationId = conversation.id;
      renderConversations();
      renderChatMessages();
    };
    list.appendChild(button);
  });
}

function renderChatMessages() {
  const container = $('#chatMessages');
  container.innerHTML = '';
  const conversation = state.conversations.find(item => item.id === state.activeConversationId);
  if (!conversation) return;
  conversation.messages.forEach(message => {
    const div = document.createElement('div');
    if (message.role === 'user') {
      div.className = 'msg user';
      div.textContent = message.content;
    } else {
      div.className = 'msg assistant';
      div.innerHTML = assistantHtml(message);
    }
    container.appendChild(div);
  });
  container.scrollTop = container.scrollHeight;
}

function assistantHtml(message) {
  let html = '';
  if (message.reasoning) html += `<div class="reasoning">${escapeHtml(message.reasoning.slice(-600))}</div>`;
  if (message.steps?.length) {
    html += '<div>' + message.steps.map((step, index) => `
      <details class="step-item">
        <summary>
          <span class="step-name">${escapeHtml(step.toolName || '工具 ' + (index + 1))}</span>
          <span class="step-state ${step.status === 'result' ? 'ok' : 'run'}">${step.status === 'result' ? '✓ 完成' : '… 执行中'}</span>
        </summary>
        <div class="step-detail">
          ${step.argsJson ? `<pre>${escapeHtml(step.argsJson)}</pre>` : ''}
          ${step.resultJson ? `<pre>${escapeHtml(String(step.resultJson).slice(0, 1200))}</pre>` : ''}
        </div>
      </details>`).join('') + '</div>';
  }
  html += renderMarkdown(message.content || (message.streaming ? '…' : '（本轮无内容返回）'));
  return html;
}

// ---------- port guard panels ----------

function readListenText() {
  const text = $('#listenInput').value.trim();
  if (!text) {
    toast('先在快照页粘贴 lsof/netstat 输出', true);
    return null;
  }
  state.lastListenText = text;
  return text;
}

async function parseSnapshot() {
  const listenText = readListenText();
  if (!listenText) return;
  const data = await request('/api/ports/snapshot', { method: 'POST', body: JSON.stringify({ listenText }) });
  $('#snapshotResult').innerHTML =
    `<div class="metric-grid">
      <div class="metric"><b>${data.listenCount}</b><span>监听</span></div>
      <div class="metric"><b>${data.publicCount}</b><span>公网</span></div>
      <div class="metric"><b>${data.wellKnownCount}</b><span>常见服务</span></div>
    </div>` +
    (data.entries || []).map(e => `
      <div class="branch-row">
        <b>${escapeHtml(e.process)}</b> <span class="badge info">:${e.port}</span>
        ${e.public ? '<span class="badge error">公网可达</span>' : '<span class="badge ok">仅本机</span>'}
        ${e.wellKnown ? `<div class="small muted">${escapeHtml(e.wellKnown)}</div>` : ''}
        <div class="small muted">${escapeHtml(e.addr)} · ${escapeHtml(e.proto)}</div>
      </div>`).join('') || '<div class="muted small">没有解析出 LISTEN 条目，检查粘贴格式</div>';
}

async function lookupProcess() {
  const listenText = readListenText();
  if (!listenText) return;
  const port = $('#portInput').value.trim();
  if (!port || !/^\d+$/.test(port)) return toast('输入数字端口号', true);
  const data = await request('/api/ports/process', { method: 'POST', body: JSON.stringify({ listenText, port: Number(port) }) });
  $('#processResult').innerHTML =
    `<div class="branch-row"><b>端口 ${data.port}</b>
      ${data.wellKnown ? `<span class="badge info">${escapeHtml(data.wellKnown)}</span>` : ''}
      <div class="small muted">${escapeHtml(data.advice)}</div>
    </div>` +
    (data.holders || []).map(h => `
      <div class="branch-row">
        <b>${escapeHtml(h.process)}</b> <span class="small muted">pid ${h.pid} · ${escapeHtml(h.user)}</span>
        <div class="small muted">${escapeHtml(h.addr)}:${h.port} ${h.public ? '· 公网可达' : '· 仅本机'}</div>
      </div>`).join('') || '<div class="muted small">快照中无此端口监听</div>';
}

async function loadConflicts() {
  const listenText = readListenText();
  if (!listenText) return;
  const data = await request('/api/ports/conflicts', { method: 'POST', body: JSON.stringify({ listenText }) });
  $('#conflictResult').innerHTML =
    `<div class="small muted">${data.issueCount} 个问题</div>` +
    (data.issues || []).map(i => `
      <div class="branch-row">
        <span class="badge ${i.type === 'db-public' ? 'error' : 'warn'}">${escapeHtml(i.type)}</span>
        <b>:${i.port}</b> ${i.process ? `<span class="small muted">${escapeHtml(String(i.process))}</span>` : ''}
        ${i.processes ? `<div class="small muted">${escapeHtml(i.processes.join(', '))}</div>` : ''}
        <div class="small muted">${escapeHtml(i.advice)}</div>
      </div>`).join('') || '<div class="muted small" style="margin-top:8px">✓ 未发现冲突问题</div>';
}

async function loadExposure() {
  const listenText = readListenText();
  if (!listenText) return;
  const data = await request('/api/ports/exposure', { method: 'POST', body: JSON.stringify({ listenText }) });
  $('#exposureResult').innerHTML =
    `<div class="metric-grid">
      <div class="metric"><b>${data.totalListen}</b><span>监听</span></div>
      <div class="metric"><b>${data.publicCount}</b><span>公网</span></div>
      <div class="metric"><b>${data.highCount}</b><span>高危</span></div>
    </div>
    <div class="small muted">${escapeHtml(data.summary)}</div>` +
    (data.findings || []).map(f => `
      <div class="branch-row">
        <span class="badge ${f.level === 'high' ? 'error' : f.level === 'medium' ? 'warn' : 'info'}">${escapeHtml(f.level)}</span>
        <b>:${f.port}</b> <span class="small muted">${escapeHtml(String(f.process))}</span>
        <div class="small muted">${escapeHtml(f.finding)}</div>
        <div class="small muted">→ ${escapeHtml(f.action)}</div>
      </div>`).join('') || '<div class="muted small" style="margin-top:8px">✓ 暴露面干净</div>';
}

async function refreshAll() {
  // 无持久数据，仅刷新快照区（若有文本）
  if ($('#listenInput').value.trim()) {
    await parseSnapshot().catch(e => toast(e.message, true));
  }
}

// ---------- chat ----------

async function sendMessage() {
  const input = $('#chatInput');
  const text = input.value.trim();
  if (!text) return;
  if (!state.activeConversationId) newConversation();
  const conversation = state.conversations.find(item => item.id === state.activeConversationId);
  if (conversation.title === '新对话') conversation.title = text.slice(0, 30);
  conversation.messages.push({ role: 'user', content: text });
  const pending = { id: createId(), role: 'assistant', content: '', reasoning: '', steps: [], streaming: true };
  conversation.messages.push(pending);
  input.value = '';
  saveConversations();
  renderConversations();
  renderChatMessages();
  setBusy(true);
  setStreamStatus('AI 正在思考');
  try {
    await streamAssistant(text, pending);
    setStreamStatus('已完成');
    setTimeout(() => setBusy(false), 450);
  } catch (error) {
    pending.content = error.name === 'AbortError' ? '**已停止生成。**' : error.message;
    setStreamStatus('执行失败');
    setTimeout(() => setBusy(false), 900);
  }
  saveConversations();
  renderChatMessages();
}

async function streamAssistant(message, pending) {
  const controller = new AbortController();
  state.activeStream = controller;
  const response = await fetch('/api/assistant/stream', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ agentId: state.activeConversationId, message }),
    signal: controller.signal
  });
  if (!response.ok || !response.body) throw new Error(`请求失败 (${response.status})`);
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  let event = 'message';
  let data = '';
  let finished = false;
  let renderQueued = false;
  const render = () => {
    if (renderQueued) return;
    renderQueued = true;
    setTimeout(() => { renderQueued = false; renderChatMessages(); }, 60);
  };
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const lines = buffer.split('\n');
    buffer = lines.pop();
    lines.forEach(line => {
      if (line.startsWith('event:')) event = line.slice(6).trim();
      else if (line.startsWith('data:')) data += `${line.slice(5).trim()}\n`;
      else if (!line && data) {
        try {
          const payload = JSON.parse(data);
          if (event === 'chunk') pending.content += payload.content || '';
          if (event === 'chunk' && pending.content) setStreamStatus('正在回复');
          if (event === 'reasoning') pending.reasoning += payload.content || '';
          if (event === 'step_break') {
            const exists = payload.callId && pending.steps.some(item => item.callId === payload.callId);
            if (!exists) pending.steps.push({ ...payload, status: 'running' });
            setStreamStatus(`正在执行 ${payload.toolName || '工具'}`);
          }
          if (event === 'tool_result') {
            const step = [...pending.steps].reverse().find(item => item.callId === payload.callId)
              || [...pending.steps].reverse().find(item => item.status === 'running');
            if (step) Object.assign(step, payload, { status: 'result' });
            else pending.steps.push({ ...payload, status: 'result' });
            setStreamStatus('正在整理结果');
          }
          if (event === 'finish' || event === 'done') {
            pending.steps.forEach(item => { if (item.status === 'running') item.status = 'result'; });
            pending.streaming = false;
            finished = true;
          }
          if (event === 'error') pending.content += `\n\n**错误：** ${payload.message || '未知错误'}`;
          render();
        } catch { }
        event = 'message';
        data = '';
      }
    });
    if (finished) break;
  }
  if (!finished) pending.streaming = false;
  state.activeStream = null;
  renderChatMessages();
}

// ---------- events ----------

$('#sendMessage').onclick = sendMessage;
$('#chatInput').addEventListener('keydown', event => {
  if ((event.metaKey || event.ctrlKey) && event.key === 'Enter') {
    event.preventDefault();
    sendMessage();
  }
});
$('#stopStream').onclick = () => state.activeStream?.abort();
$('#newConversation').onclick = () => { newConversation(); };

$('#snapshotBtn').onclick = () => parseSnapshot().catch(e => toast(e.message, true));
$('#probeBtn').onclick = async () => {
  try {
    const data = await request('/api/ports/live-probe');
    if (data.probeAvailable && data.sample) {
      $('#listenInput').value = data.sample;
      toast('已填入本机监听样本');
      await parseSnapshot();
    } else {
      toast(data.note, true);
    }
  } catch (error) {
    toast(error.message, true);
  }
};
$('#processBtn').onclick = () => lookupProcess().catch(e => toast(e.message, true));
$('#portInput').addEventListener('keydown', e => { if (e.key === 'Enter') $('#processBtn').click(); });
$('#conflictBtn').onclick = () => loadConflicts().catch(e => toast(e.message, true));
$('#exposureBtn').onclick = () => loadExposure().catch(e => toast(e.message, true));

$('#openDraft').onclick = () => $('#draftModal').classList.remove('hidden');
$('#cancelDraftModal').onclick = () => $('#draftModal').classList.add('hidden');
$('#draftForm').onsubmit = async event => {
  event.preventDefault();
  const form = new FormData(event.target);
  try {
    const data = await request('/api/ports/fw-draft', {
      method: 'POST',
      body: JSON.stringify({
        style: form.get('style'),
        allowPort: Number(form.get('allowPort')) || 443,
        source: form.get('source'),
        denyNote: form.get('denyNote')
      })
    });
    $('#draftModal').classList.add('hidden');
    $('#exposureResult').innerHTML =
      `<div class="small muted"><b>${escapeHtml(data.style)}</b> 草稿 · ${data.lineCount} 行 · 放行 ${data.allowPort}/tcp 来自 ${escapeHtml(data.source)}</div>
      <pre class="small" style="white-space:pre-wrap;background:var(--bg);padding:8px;border-radius:8px;border:1px solid var(--border)">${escapeHtml(data.lines.join('\n'))}</pre>` +
      (data.notes || []).map(n => `<div class="small muted">⚠ ${escapeHtml(n)}</div>`).join('');
    document.querySelector('[data-resource-tab="exposure"]').click();
    toast('草稿已生成（未执行）');
  } catch (error) {
    toast(error.message, true);
  }
};

$('#refreshResource').onclick = async () => {
  await refreshAll();
  toast('已刷新');
};
document.querySelectorAll('[data-resource-tab]').forEach(button => {
  button.onclick = () => {
    document.querySelectorAll('[data-resource-tab]').forEach(item => item.classList.toggle('active', item === button));
    document.querySelectorAll('[data-tab]').forEach(panel => panel.classList.toggle('hidden', panel.dataset.tab !== button.dataset.resourceTab));
  };
});
$('#toggleTheme').onclick = () => {
  const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  localStorage.setItem('dsh.portguard.theme', next);
  $('#toggleTheme').textContent = next === 'dark' ? '☀️' : '🌙';
};
document.documentElement.dataset.theme = localStorage.getItem('dsh.portguard.theme') || 'light';
$('#toggleTheme').textContent = document.documentElement.dataset.theme === 'dark' ? '☀️' : '🌙';

// ---------- init ----------

(async function init() {
  loadConversations();
  if (!state.conversations.length) newConversation();
  else { state.activeConversationId = state.conversations[0].id; }
  renderConversations();
  renderChatMessages();
  try {
    await refreshAll();
  } catch (error) {
    toast(error.message, true);
  }
})();
