const state = {
	prefix: "",
	items: { folders: [], files: [] },
	search: ""
};

function fmtBytes(bytes) {
	const thresh = 1024;
	if (Math.abs(bytes) < thresh) return bytes + ' B';
	const units = ['KB','MB','GB','TB','PB'];
	let u = -1;
	do { bytes /= thresh; ++u; } while (Math.abs(bytes) >= thresh && u < units.length - 1);
	return bytes.toFixed(1) + ' ' + units[u];
}

async function api(path, options = {}) {
	const res = await fetch(path, {
		...options,
		headers: {
			'authorization': localStorage.getItem('auth') || '',
			...(options.headers || {})
		}
	});
	if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || res.statusText);
	return res.headers.get('content-type')?.includes('application/json') ? res.json() : res;
}

function renderBreadcrumbs() {
	const bc = document.getElementById('breadcrumbs');
	const parts = state.prefix.split('/').filter(Boolean);
	let acc = '';
	const nodes = [link('/', () => goTo(''))];
	for (const part of parts) {
		acc += part + '/';
		nodes.push(document.createTextNode(' / '));
		nodes.push(link(part, () => goTo(acc)));
	}
	bc.replaceChildren(...nodes);
}

function link(text, onClick) {
	const a = document.createElement('button');
	a.textContent = text;
	a.className = 'text-white/80 hover:text-white underline-offset-4 hover:underline';
	a.onclick = onClick;
	return a;
}

function row(cells) {
	const tr = document.createElement('tr');
	cells.forEach(td => tr.appendChild(td));
	return tr;
}

function td(content, cls = '') {
	const el = document.createElement('td');
	el.className = `px-4 py-2 ${cls}`;
	if (content instanceof Node) el.appendChild(content); else el.textContent = content;
	return el;
}

function button(label, cls, onClick) {
	const b = document.createElement('button');
	b.textContent = label;
	b.className = cls;
	b.onclick = onClick;
	return b;
}

function renderTable() {
	const tbody = document.getElementById('fileTable');
	tbody.innerHTML = '';
	const q = state.search.toLowerCase();
	for (const f of state.items.folders.filter(x => x.name.toLowerCase().includes(q))) {
		const nameBtn = link(f.name, () => goTo(f.path));
		tbody.appendChild(row([
			td(nameBtn),
			td('—', 'text-white/40'),
			td(''),
			td('')
		]));
	}
	for (const f of state.items.files.filter(x => x.name.toLowerCase().includes(q))) {
		const name = td(f.name);
		const size = td(fmtBytes(f.size), 'text-white/60');
		const mod = td(f.uploadedAt ? new Date(f.uploadedAt).toLocaleString() : '', 'text-white/60');
		const actions = td('', 'text-right');
		const dl = button('Download', 'px-2 py-1 rounded-md bg-white/5 hover:bg-white/10', () => download(f.key));
		const del = button('Delete', 'ml-2 px-2 py-1 rounded-md bg-red-500/10 text-red-300 hover:bg-red-500/20', () => remove(f.key));
		actions.append(dl, del);
		tbody.appendChild(row([name, size, mod, actions]));
	}
}

async function list() {
	const data = await api(`/api/files?prefix=${encodeURIComponent(state.prefix)}`);
	state.items = data;
	renderBreadcrumbs();
	renderTable();
}

async function goTo(prefix) {
	state.prefix = prefix;
	await list();
}

async function download(key) {
	const res = await api(`/api/download?key=${encodeURIComponent(key)}`);
	const blob = await res.blob();
	const a = document.createElement('a');
	a.href = URL.createObjectURL(blob);
	a.download = key.split('/').pop() || 'file';
	document.body.appendChild(a);
	a.click();
	a.remove();
	URL.revokeObjectURL(a.href);
}

async function remove(key) {
	if (!confirm('Delete this file?')) return;
	await api(`/api/file?key=${encodeURIComponent(key)}`, { method: 'DELETE' });
	await list();
}

function setupUpload() {
	const input = document.getElementById('fileInput');
	input.addEventListener('change', async () => {
		for (const file of input.files || []) {
			const path = `${state.prefix}${file.name}`;
			await api(`/api/upload?path=${encodeURIComponent(path)}`, { method: 'POST', body: file, headers: { 'content-type': file.type || 'application/octet-stream' } });
		}
		input.value = '';
		await list();
	});

	const dz = document.getElementById('dropZone');
	dz.addEventListener('dragover', e => { e.preventDefault(); dz.classList.add('ring-2','ring-white/10'); });
	dz.addEventListener('dragleave', () => dz.classList.remove('ring-2','ring-white/10'));
	dz.addEventListener('drop', async e => {
		e.preventDefault(); dz.classList.remove('ring-2','ring-white/10');
		const files = e.dataTransfer?.files || [];
		for (const file of files) {
			const path = `${state.prefix}${file.name}`;
			await api(`/api/upload?path=${encodeURIComponent(path)}`, { method: 'POST', body: file, headers: { 'content-type': file.type || 'application/octet-stream' } });
		}
		await list();
	});
}

function setupFolderCreate() {
	document.getElementById('newFolderBtn').addEventListener('click', async () => {
		const name = prompt('Folder name');
		if (!name) return;
		await api('/api/folder', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ name, prefix: state.prefix }) });
		await list();
	});
}

function setupSearch() {
	const input = document.getElementById('searchInput');
	input.addEventListener('input', () => { state.search = input.value; renderTable(); });
	document.getElementById('refreshBtn').addEventListener('click', list);
}

function setupAuth() {
	const url = new URL(location.href);
	const qpToken = url.searchParams.get('token');
	if (qpToken) {
		localStorage.setItem('auth', `Bearer ${qpToken}`);
		url.searchParams.delete('token');
		history.replaceState({}, '', url.pathname + url.search + url.hash);
	}
	if (!localStorage.getItem('auth')) {
		const token = prompt('Paste your Bearer token (Authorization header)');
		if (token) localStorage.setItem('auth', `Bearer ${token}`);
	}
	document.getElementById('signOutBtn')?.addEventListener('click', () => {
		localStorage.removeItem('auth');
		location.reload();
	});
}

async function init() {
	setupAuth();
	setupUpload();
	setupFolderCreate();
	setupSearch();
	await list();
}

init().catch(err => alert(err.message));