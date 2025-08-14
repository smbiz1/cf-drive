export interface Env {
	bucket: R2Bucket;
	ASSETS: Fetcher;
	// Optional configuration
	JWT_SECRET?: string; // HS256 secret for verifying Authorization: Bearer tokens from your main app
	READONLY?: string; // "true" to disable write operations
}

// ---- Utility: JSON response helpers ----
function json(data: unknown, init: ResponseInit = {}): Response {
	const headers = new Headers(init.headers);
	headers.set("content-type", "application/json; charset=utf-8");
	return new Response(JSON.stringify(data), { ...init, headers });
}

function error(status: number, message: string): Response {
	return json({ error: message }, { status });
}

// ---- Base64url helpers ----
function base64UrlToUint8Array(b64url: string): Uint8Array {
	let b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
	while (b64.length % 4) b64 += "=";
	const bin = atob(b64);
	const bytes = new Uint8Array(bin.length);
	for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
	return bytes;
}

function base64UrlToString(b64url: string): string {
	let b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
	while (b64.length % 4) b64 += "=";
	return atob(b64);
}

// ---- Auth and tenancy ----
interface AuthContext {
	tenantId: string;
	userId: string;
	role: "user" | "tenant-admin" | "admin";
}

async function verifyHs256Jwt(token: string, secret: string): Promise<Record<string, any> | null> {
	try {
		const [headerB64, payloadB64, signatureB64] = token.split(".");
		if (!headerB64 || !payloadB64 || !signatureB64) return null;
		const enc = new TextEncoder();
		const key = await crypto.subtle.importKey(
			"raw",
			enc.encode(secret),
			{ name: "HMAC", hash: "SHA-256" },
			false,
			["verify"]
		);
		const dataBytes = enc.encode(`${headerB64}.${payloadB64}`);
		const sigBytes = base64UrlToUint8Array(signatureB64);
		const valid = await crypto.subtle.verify("HMAC", key, sigBytes, dataBytes);
		if (!valid) return null;
		const payloadJson = base64UrlToString(payloadB64);
		return JSON.parse(payloadJson);
	} catch {
		return null;
	}
}

async function requireAuth(request: Request, env: Env): Promise<AuthContext | null> {
	// Expect Authorization: Bearer <jwt> with claims { tid, uid, role }
	const auth = request.headers.get("authorization") || request.headers.get("Authorization");
	if (!auth || !auth.toLowerCase().startsWith("bearer ")) return null;
	const token = auth.slice(7).trim();
	if (!env.JWT_SECRET) return null;
	const payload = await verifyHs256Jwt(token, env.JWT_SECRET);
	if (!payload) return null;
	const tenantId = String(payload.tid || "").trim();
	const userId = String(payload.uid || "").trim();
	const role = (payload.role as AuthContext["role"]) || "user";
	if (!tenantId || !userId) return null;
	return { tenantId, userId, role };
}

function resolveBasePrefix(auth: AuthContext): string {
	if (auth.role === "admin" || auth.role === "tenant-admin") {
		return `tenant/${auth.tenantId}/`;
	}
	return `tenant/${auth.tenantId}/users/${auth.userId}/`;
}

function isReadonly(env: Env): boolean {
	return (env.READONLY || "true").toLowerCase() === "true";
}

// ---- R2 helpers ----
async function listObjects(bucket: R2Bucket, prefix: string, cursor?: string) {
	return bucket.list({ prefix, delimiter: "/", limit: 1000, cursor });
}

function sanitizeKey(basePrefix: string, key: string): string | null {
	const normalized = key.replace(/\\+/g, "/").replace(/\.{2,}/g, ".");
	const full = basePrefix + normalized.replace(/^\/+/, "");
	if (!full.startsWith(basePrefix)) return null;
	return full;
}

// ---- Router ----
export default {
	async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
		const url = new URL(request.url);

		// Serve API
		if (url.pathname.startsWith("/api/")) {
			const auth = await requireAuth(request, env);
			if (!auth) return error(401, "Unauthorized");
			const basePrefix = resolveBasePrefix(auth);

			// GET /api/files?prefix=encodedSubPath
			if (request.method === "GET" && url.pathname === "/api/files") {
				const sub = decodeURIComponent(url.searchParams.get("prefix") || "");
				const prefix = sanitizeKey(basePrefix, sub === "/" ? "" : sub) || basePrefix;
				const list = await listObjects(env.bucket, prefix);
				const folders = list.delimitedPrefixes?.map(p => ({
					name: p.slice(prefix.length).replace(/\/$/, ""),
					path: p.slice(basePrefix.length)
				})) || [];
				const files = list.objects?.map(o => ({
					name: o.key.slice(prefix.length),
					key: o.key.slice(basePrefix.length),
					size: o.size,
					uploadedAt: o.uploaded?.toISOString() || null,
					httpMetadata: o.httpMetadata || null,
					customMetadata: o.customMetadata || null
				})) || [];
				return json({ base: basePrefix, prefix: prefix.slice(basePrefix.length), folders, files });
			}

			// GET /api/download?key=encodedKey
			if (request.method === "GET" && url.pathname === "/api/download") {
				const keyParam = url.searchParams.get("key");
				if (!keyParam) return error(400, "Missing key");
				const key = sanitizeKey(basePrefix, decodeURIComponent(keyParam));
				if (!key) return error(400, "Invalid key");
				const obj = await env.bucket.get(key);
				if (!obj) return error(404, "Not found");
				const headers = new Headers();
				const meta = obj.httpMetadata as R2HTTPMetadata | undefined;
				if (meta?.contentType) headers.set("content-type", meta.contentType);
				if (meta?.contentLanguage) headers.set("content-language", meta.contentLanguage);
				if (meta?.contentDisposition) headers.set("content-disposition", meta.contentDisposition);
				if (meta?.contentEncoding) headers.set("content-encoding", meta.contentEncoding);
				if (meta?.cacheControl) headers.set("cache-control", meta.cacheControl);
				headers.set("content-length", String(obj.size));
				if (obj.etag) headers.set("etag", obj.etag);
				if (obj.uploaded) headers.set("last-modified", obj.uploaded.toUTCString());
				return new Response(obj.body, { headers });
			}

			// POST /api/upload?path=encodedPath
			if (request.method === "POST" && url.pathname === "/api/upload") {
				if (isReadonly(env)) return error(403, "Readonly mode");
				const pathParam = url.searchParams.get("path") || "";
				const key = sanitizeKey(basePrefix, decodeURIComponent(pathParam));
				if (!key) return error(400, "Invalid path");
				const httpMeta: R2HTTPMetadata = {};
				const contentType = request.headers.get("content-type");
				if (contentType) httpMeta.contentType = contentType;
				const put = await env.bucket.put(key, request.body, { httpMetadata: httpMeta });
				return json({ ok: true, key: put.key.slice(basePrefix.length) });
			}

			// DELETE /api/file?key=encodedKey
			if (request.method === "DELETE" && url.pathname === "/api/file") {
				if (isReadonly(env)) return error(403, "Readonly mode");
				const keyParam = url.searchParams.get("key");
				if (!keyParam) return error(400, "Missing key");
				const key = sanitizeKey(basePrefix, decodeURIComponent(keyParam));
				if (!key) return error(400, "Invalid key");
				await env.bucket.delete(key);
				return json({ ok: true });
			}

			// POST /api/folder with JSON { name, prefix }
			if (request.method === "POST" && url.pathname === "/api/folder") {
				if (isReadonly(env)) return error(403, "Readonly mode");
				const body = await request.json().catch(() => null) as { name?: string; prefix?: string } | null;
				if (!body || !body.name) return error(400, "Missing name");
				const parent = body.prefix ? decodeURIComponent(body.prefix) : "";
				const full = sanitizeKey(basePrefix, `${parent}/${body.name}`.replace(/\/+/, "/"));
				if (!full) return error(400, "Invalid folder name");
				await env.bucket.put(`${full.replace(/\/$/, "")}/`, new Uint8Array());
				return json({ ok: true });
			}

			// PATCH /api/metadata?key=... body: { httpMetadata?, customMetadata? }
			if (request.method === "PATCH" && url.pathname === "/api/metadata") {
				if (isReadonly(env)) return error(403, "Readonly mode");
				const keyParam = url.searchParams.get("key");
				if (!keyParam) return error(400, "Missing key");
				const key = sanitizeKey(basePrefix, decodeURIComponent(keyParam));
				if (!key) return error(400, "Invalid key");
				const body = await request.json().catch(() => null) as { httpMetadata?: R2HTTPMetadata; customMetadata?: Record<string, string> } | null;
				if (!body) return error(400, "Invalid body");
				const existing = await env.bucket.get(key);
				const data = existing ? await existing.arrayBuffer() : new Uint8Array();
				await env.bucket.put(key, data, {
					httpMetadata: body.httpMetadata,
					customMetadata: body.customMetadata
				});
				return json({ ok: true });
			}

			return error(404, "Not found");
		}

		// Non-API: serve static assets (SPA)
		const assetResponse = await env.ASSETS.fetch(request);
		return assetResponse;
	}
};
