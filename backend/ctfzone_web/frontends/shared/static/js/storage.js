import { apiRequest, idempotencyHeaders } from "./api.js";

const configuredOrigin = document
  .querySelector('meta[name="object-storage-origin"]')
  ?.content?.trim() || "";
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const browserHashLimitBytes = 64 * 1024 * 1024;

function storageOrigin() {
  if (!configuredOrigin) throw new Error("Direct object storage is not configured.");
  let parsed;
  try {
    parsed = new URL(configuredOrigin);
  } catch (_error) {
    throw new Error("Direct object storage is misconfigured.");
  }
  if (
    !["http:", "https:"].includes(parsed.protocol)
    || parsed.username
    || parsed.password
    || parsed.pathname !== "/"
    || parsed.search
    || parsed.hash
  ) {
    throw new Error("Direct object storage is misconfigured.");
  }
  return parsed.origin;
}

function validatedUploadUrl(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch (_error) {
    throw new Error("The API returned an invalid upload destination.");
  }
  if (
    parsed.origin !== storageOrigin()
    || parsed.username
    || parsed.password
    || parsed.hash
  ) {
    throw new Error("The API returned an untrusted upload destination.");
  }
  return parsed.href;
}

function validatedUploadHeaders(value, expectedContentType, expectedChecksum) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("The API returned invalid upload headers.");
  }
  const headers = {};
  const normalizedHeaders = new Map();
  for (const [name, headerValue] of Object.entries(value)) {
    const normalized = name.toLowerCase();
    if (
      typeof headerValue !== "string"
      || !["content-type", "x-amz-checksum-sha256"].includes(normalized)
      || normalizedHeaders.has(normalized)
    ) {
      throw new Error("The API returned an unsafe upload header.");
    }
    headers[name] = headerValue;
    normalizedHeaders.set(normalized, headerValue);
  }
  if (normalizedHeaders.get("content-type") !== expectedContentType) {
    throw new Error("The API did not bind the expected upload content type.");
  }
  if (normalizedHeaders.get("x-amz-checksum-sha256") !== expectedChecksum) {
    throw new Error("The API did not bind the expected upload checksum.");
  }
  return headers;
}

function validatedCompletionPath(value, objectId) {
  const expected = `/bff/api/v1/storage/objects/${objectId}/complete`;
  if (value !== expected) throw new Error("The API returned an invalid completion path.");
  return value.slice("/bff".length);
}

async function sha256(file) {
  if (!globalThis.crypto?.subtle) {
    throw new Error("This browser cannot securely hash files for upload.");
  }
  if (!Number.isSafeInteger(file.size) || file.size < 0 || file.size > browserHashLimitBytes) {
    throw new Error("Admin uploads are limited to 64 MiB per file.");
  }
  // WebCrypto has no streaming digest API. Keep this bounded until the UI gains
  // a reviewed incremental SHA-256 implementation or worker-based hasher.
  const digest = new Uint8Array(
    await globalThis.crypto.subtle.digest("SHA-256", await file.arrayBuffer()),
  );
  const hex = Array.from(digest, byte => byte.toString(16).padStart(2, "0")).join("");
  const base64 = globalThis.btoa(String.fromCharCode(...digest));
  return { hex, base64 };
}

/**
 * Authorize metadata through the BFF, send bytes straight to object storage,
 * then authorize completion through the BFF. The signed storage URL is the
 * only cross-origin browser request and deliberately receives no credentials.
 */
export async function uploadObject(file, { purpose, ...target }) {
  if (!(file instanceof File) || !file.name) throw new TypeError("Choose a file to upload.");
  const checksum = await sha256(file);
  const contentType = file.type || "application/octet-stream";
  const metadata = {
    purpose,
    filename: file.name,
    content_type: contentType,
    size: file.size,
    sha256: checksum.hex,
    ...target,
  };
  const initiated = await apiRequest("/api/v1/storage/uploads", {
    method: "POST",
    headers: idempotencyHeaders(),
    body: metadata,
  });
  const grant = initiated.data;
  const objectId = String(grant?.object?.id || "");
  if (!uuidPattern.test(objectId)) throw new Error("The API returned an invalid object identifier.");
  if (grant?.object?.status === "ready" && !grant?.upload) return grant.object;
  if (grant?.upload?.method !== "PUT") throw new Error("The API returned an unsupported upload method.");

  const uploadUrl = validatedUploadUrl(grant.upload.url);
  const uploadHeaders = validatedUploadHeaders(
    grant.upload.headers,
    contentType,
    checksum.base64,
  );
  const completePath = validatedCompletionPath(grant.complete_path, objectId);
  const uploaded = await fetch(uploadUrl, {
    method: "PUT",
    headers: uploadHeaders,
    body: file,
    credentials: "omit",
    redirect: "error",
    referrerPolicy: "no-referrer",
    mode: "cors",
  });
  if (!uploaded.ok) throw new Error(`Object storage rejected the upload (${uploaded.status}).`);

  const completed = await apiRequest(completePath, { method: "POST" });
  return completed.data;
}
