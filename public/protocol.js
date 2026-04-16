"use strict";
(() => {
  var __create = Object.create;
  var __defProp = Object.defineProperty;
  var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
  var __getOwnPropNames = Object.getOwnPropertyNames;
  var __getProtoOf = Object.getPrototypeOf;
  var __hasOwnProp = Object.prototype.hasOwnProperty;
  var __commonJS = (cb, mod) => function __require() {
    return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
  };
  var __copyProps = (to, from, except, desc) => {
    if (from && typeof from === "object" || typeof from === "function") {
      for (let key of __getOwnPropNames(from))
        if (!__hasOwnProp.call(to, key) && key !== except)
          __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
    }
    return to;
  };
  var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
    // If the importer is in node compatibility mode or this is not an ESM
    // file that has been converted to a CommonJS file using a Babel-
    // compatible transform (i.e. "__esModule" has not been set), then set
    // "default" to the CommonJS "module.exports" for node compatibility.
    isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
    mod
  ));

  // node_modules/@hellocoop/httpsig/dist/types.js
  var require_types = __commonJS({
    "node_modules/@hellocoop/httpsig/dist/types.js"(exports) {
      "use strict";
      Object.defineProperty(exports, "__esModule", { value: true });
      exports.DEFAULT_COMPONENTS_BODY = exports.DEFAULT_COMPONENTS_GET = exports.VALID_DERIVED_COMPONENTS = void 0;
      exports.VALID_DERIVED_COMPONENTS = [
        "@method",
        "@target-uri",
        "@authority",
        "@scheme",
        "@request-target",
        "@path",
        "@query",
        "@query-param",
        "@status"
      ];
      exports.DEFAULT_COMPONENTS_GET = [
        "@method",
        "@authority",
        "@path",
        "signature-key"
      ];
      exports.DEFAULT_COMPONENTS_BODY = [
        "@method",
        "@authority",
        "@path",
        "content-type",
        "signature-key"
      ];
    }
  });

  // node_modules/@hellocoop/httpsig/dist/utils/crypto.js
  var require_crypto = __commonJS({
    "node_modules/@hellocoop/httpsig/dist/utils/crypto.js"(exports) {
      "use strict";
      Object.defineProperty(exports, "__esModule", { value: true });
      exports.getAlgorithmFromJwk = getAlgorithmFromJwk;
      exports.importPrivateKey = importPrivateKey;
      exports.importPublicKey = importPublicKey;
      exports.getPublicJwk = getPublicJwk;
      exports.sign = sign;
      exports.verify = verify;
      exports.generateKeyPair = generateKeyPair;
      exports.validateJwk = validateJwk;
      function getAlgorithmFromJwk(jwk) {
        if (jwk.kty === "OKP") {
          if (jwk.crv === "Ed25519") {
            return { name: "Ed25519" };
          }
          throw new Error(`Unsupported OKP curve: ${jwk.crv}`);
        }
        if (jwk.kty === "EC") {
          if (jwk.crv === "P-256") {
            return { name: "ECDSA", namedCurve: "P-256", hash: "SHA-256" };
          }
          throw new Error(`Unsupported EC curve: ${jwk.crv}`);
        }
        throw new Error(`Unsupported key type: ${jwk.kty}`);
      }
      async function importPrivateKey(jwk) {
        const algorithm = getAlgorithmFromJwk(jwk);
        return await crypto.subtle.importKey("jwk", jwk, algorithm, false, ["sign"]);
      }
      async function importPublicKey(jwk) {
        const algorithm = getAlgorithmFromJwk(jwk);
        return await crypto.subtle.importKey("jwk", jwk, algorithm, false, [
          "verify"
        ]);
      }
      function getPublicJwk(privateJwk) {
        const { d, p, q, dp, dq, qi, ...publicJwk } = privateJwk;
        return publicJwk;
      }
      async function sign(data, privateKey, algorithm) {
        const signature = await crypto.subtle.sign(algorithm, privateKey, data);
        return new Uint8Array(signature);
      }
      async function verify(data, signature, publicKey, algorithm) {
        return await crypto.subtle.verify(algorithm, publicKey, signature, data);
      }
      async function generateKeyPair(options) {
        const algorithm = options?.algorithm ?? "Ed25519";
        const extractable = options?.extractable ?? true;
        let genAlgorithm;
        let keyUsages = ["sign", "verify"];
        if (algorithm === "Ed25519") {
          genAlgorithm = { name: "Ed25519" };
        } else if (algorithm === "ES256") {
          genAlgorithm = { name: "ECDSA", namedCurve: "P-256" };
        } else {
          throw new Error(`Unsupported algorithm: ${algorithm}`);
        }
        const keyPair = await crypto.subtle.generateKey(genAlgorithm, extractable, keyUsages);
        const publicKey = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
        return {
          privateKey: keyPair.privateKey,
          publicKey
        };
      }
      function validateJwk(jwk) {
        if (!jwk.kty) {
          throw new Error("JWK missing required field: kty");
        }
        if (jwk.kty === "OKP") {
          if (!jwk.crv)
            throw new Error("OKP JWK missing required field: crv");
          if (!jwk.x)
            throw new Error("OKP JWK missing required field: x");
        } else if (jwk.kty === "EC") {
          if (!jwk.crv)
            throw new Error("EC JWK missing required field: crv");
          if (!jwk.x)
            throw new Error("EC JWK missing required field: x");
          if (!jwk.y)
            throw new Error("EC JWK missing required field: y");
        } else {
          throw new Error(`Unsupported key type: ${jwk.kty}`);
        }
      }
    }
  });

  // node_modules/@hellocoop/httpsig/dist/utils/base64.js
  var require_base64 = __commonJS({
    "node_modules/@hellocoop/httpsig/dist/utils/base64.js"(exports) {
      "use strict";
      Object.defineProperty(exports, "__esModule", { value: true });
      exports.base64urlEncode = base64urlEncode;
      exports.base64urlDecode = base64urlDecode;
      exports.base64Encode = base64Encode;
      exports.base64Decode = base64Decode;
      exports.sha256 = sha256;
      exports.sha512 = sha512;
      function bytesToBase64(bytes) {
        let binary = "";
        for (let i = 0; i < bytes.length; i++) {
          binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
      }
      function base64ToBytes(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
          bytes[i] = binary.charCodeAt(i);
        }
        return bytes;
      }
      function base64urlEncode(data) {
        const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
        const base64 = bytesToBase64(bytes);
        return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
      }
      function base64urlDecode(data) {
        let padded = data;
        const padding = (4 - data.length % 4) % 4;
        if (padding > 0) {
          padded += "=".repeat(padding);
        }
        const base64 = padded.replace(/-/g, "+").replace(/_/g, "/");
        return base64ToBytes(base64);
      }
      function base64Encode(data) {
        const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
        return bytesToBase64(bytes);
      }
      function base64Decode(data) {
        return base64ToBytes(data);
      }
      async function sha256(data) {
        const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
        const hashBuffer = await crypto.subtle.digest("SHA-256", bytes);
        return new Uint8Array(hashBuffer);
      }
      async function sha512(data) {
        const bytes = typeof data === "string" ? new TextEncoder().encode(data) : data;
        const hashBuffer = await crypto.subtle.digest("SHA-512", bytes);
        return new Uint8Array(hashBuffer);
      }
    }
  });

  // node_modules/@hellocoop/httpsig/dist/utils/signature.js
  var require_signature = __commonJS({
    "node_modules/@hellocoop/httpsig/dist/utils/signature.js"(exports) {
      "use strict";
      Object.defineProperty(exports, "__esModule", { value: true });
      exports.generateSignatureBase = generateSignatureBase;
      exports.generateSignatureInputHeader = generateSignatureInputHeader;
      exports.generateSignatureKeyHeader = generateSignatureKeyHeader;
      exports.generateSignatureHeader = generateSignatureHeader;
      exports.generateContentDigest = generateContentDigest;
      exports.parseSignatureInput = parseSignatureInput;
      exports.parseSignatureKey = parseSignatureKey;
      exports.generateSignatureErrorHeader = generateSignatureErrorHeader;
      exports.parseSignatureError = parseSignatureError;
      exports.generateAcceptSignatureHeader = generateAcceptSignatureHeader;
      exports.parseAcceptSignature = parseAcceptSignature;
      exports.parseSignature = parseSignature;
      var base64_js_1 = require_base64();
      function generateSignatureBase(components, componentValues) {
        const lines = [];
        for (const component of components) {
          const value = componentValues.get(component);
          if (value === void 0) {
            throw new Error(`Missing value for component: ${component}`);
          }
          lines.push(`"${component}": ${value}`);
        }
        return lines.join("\n");
      }
      function generateSignatureInputHeader(label, components, created) {
        const componentList = components.map((c) => `"${c}"`).join(" ");
        return `${label}=(${componentList});created=${created}`;
      }
      function generateSignatureKeyHeader(label, signatureKey, publicJwk) {
        if (signatureKey.type === "hwk") {
          if (!publicJwk) {
            throw new Error("Public JWK required for hwk signature key type");
          }
          const params = [`kty="${publicJwk.kty}"`];
          if (publicJwk.crv)
            params.push(`crv="${publicJwk.crv}"`);
          if (publicJwk.x)
            params.push(`x="${publicJwk.x}"`);
          if (publicJwk.y)
            params.push(`y="${publicJwk.y}"`);
          if (publicJwk.n)
            params.push(`n="${publicJwk.n}"`);
          if (publicJwk.e)
            params.push(`e="${publicJwk.e}"`);
          return `${label}=hwk;${params.join(";")}`;
        }
        if (signatureKey.type === "jwt") {
          return `${label}=jwt;jwt="${signatureKey.jwt}"`;
        }
        if (signatureKey.type === "jkt_jwt") {
          return `${label}=jkt-jwt;jwt="${signatureKey.jwt}"`;
        }
        if (signatureKey.type === "jwks_uri") {
          const params = [
            `id="${signatureKey.id}"`,
            `dwk="${signatureKey.dwk}"`,
            `kid="${signatureKey.kid}"`
          ];
          return `${label}=jwks_uri;${params.join(";")}`;
        }
        throw new Error(`Unsupported signature key type: ${signatureKey.type}`);
      }
      function generateSignatureHeader(label, signature) {
        const encoded = (0, base64_js_1.base64Encode)(signature);
        return `${label}=:${encoded}:`;
      }
      async function generateContentDigest(body) {
        let bytes;
        if (typeof body === "string") {
          bytes = new TextEncoder().encode(body);
        } else if (body instanceof Uint8Array) {
          bytes = body;
        } else if (body instanceof ArrayBuffer) {
          bytes = new Uint8Array(body);
        } else if (Buffer.isBuffer(body)) {
          bytes = new Uint8Array(body);
        } else {
          bytes = new TextEncoder().encode(String(body));
        }
        const hash = await (0, base64_js_1.sha256)(bytes);
        const encoded = (0, base64_js_1.base64Encode)(hash);
        return `sha-256=:${encoded}:`;
      }
      function parseSignatureInput(header) {
        const results = [];
        const parts = header.split(",").map((p) => p.trim());
        for (const part of parts) {
          const match = part.match(/^([^=]+)=\(([^)]*)\);(.+)$/);
          if (!match) {
            throw new Error(`Invalid Signature-Input format: ${part}`);
          }
          const label = match[1].trim();
          const componentsStr = match[2];
          const paramsStr = match[3];
          const components = componentsStr.split(/\s+/).map((c) => c.replace(/"/g, "")).filter((c) => c);
          const params = {};
          const paramPairs = paramsStr.split(";").map((p) => p.trim());
          for (const pair of paramPairs) {
            const [key, value] = pair.split("=").map((s) => s.trim());
            if (key === "created") {
              params.created = parseInt(value, 10);
            } else {
              params[key] = value;
            }
          }
          if (!params.created) {
            throw new Error("Signature-Input missing required parameter: created");
          }
          results.push({ label, components, params });
        }
        return results;
      }
      function parseSignatureKey(header) {
        const trimmed = header.trim();
        let inQuote = false;
        for (let i = 0; i < trimmed.length; i++) {
          if (trimmed[i] === '"' && (i === 0 || trimmed[i - 1] !== "\\")) {
            inQuote = !inQuote;
          } else if (trimmed[i] === "," && !inQuote) {
            throw new Error("Invalid Signature-Key: must have exactly one dictionary member");
          }
        }
        const match = trimmed.match(/^([\w-]+)=([\w-]+)(.*)$/);
        if (!match) {
          throw new Error("Invalid Signature-Key: must be RFC 8941 Dictionary with format label=scheme;params");
        }
        const label = match[1];
        const scheme = match[2];
        const paramsStr = match[3];
        const params = {};
        if (paramsStr) {
          const paramMatches = paramsStr.matchAll(/;([\w-]+)=(?:"([^"]*)"|(\w+))/g);
          for (const paramMatch of paramMatches) {
            const key = paramMatch[1];
            const value = paramMatch[2] !== void 0 ? paramMatch[2] : paramMatch[3];
            params[key] = value;
          }
        }
        if (!["hwk", "jwt", "jkt-jwt", "jwks_uri", "x509"].includes(scheme)) {
          throw new Error(`Unsupported Signature-Key scheme: ${scheme}`);
        }
        if (scheme === "hwk") {
          if (!params.kty) {
            throw new Error("Signature-Key hwk scheme missing kty parameter");
          }
          return [{ label, type: "hwk", value: params }];
        }
        if (scheme === "jwt") {
          if (!params.jwt) {
            throw new Error("Signature-Key jwt scheme missing jwt parameter");
          }
          return [
            {
              label,
              type: "jwt",
              value: { jwt: params.jwt }
            }
          ];
        }
        if (scheme === "jkt-jwt") {
          if (!params.jwt) {
            throw new Error("Signature-Key jkt-jwt scheme missing jwt parameter");
          }
          return [
            {
              label,
              type: "jkt_jwt",
              value: { jwt: params.jwt }
            }
          ];
        }
        if (scheme === "jwks_uri") {
          if (!params.id || !params.dwk || !params.kid) {
            throw new Error("Signature-Key jwks_uri scheme missing required id/dwk/kid parameters");
          }
          return [
            {
              label,
              type: "jwks_uri",
              value: {
                id: params.id,
                kid: params.kid,
                dwk: params.dwk
              }
            }
          ];
        }
        throw new Error(`Unsupported Signature-Key scheme: ${scheme}`);
      }
      function generateSignatureErrorHeader(signatureError) {
        const parts = [`error=${signatureError.error}`];
        if (signatureError.supported_algorithms) {
          const algList = signatureError.supported_algorithms.map((a) => `"${a}"`).join(" ");
          parts.push(`supported_algorithms=(${algList})`);
        }
        if (signatureError.required_input) {
          const inputList = signatureError.required_input.map((c) => `"${c}"`).join(" ");
          parts.push(`required_input=(${inputList})`);
        }
        return parts.join(", ");
      }
      function parseSignatureError(header) {
        const trimmed = header.trim();
        const errorMatch = trimmed.match(/error=([\w]+)/);
        if (!errorMatch) {
          throw new Error("Invalid Signature-Error: missing error member");
        }
        const error = errorMatch[1];
        const validCodes = [
          "unsupported_algorithm",
          "invalid_signature",
          "invalid_input",
          "invalid_request",
          "invalid_key",
          "unknown_key",
          "invalid_jwt",
          "expired_jwt"
        ];
        if (!validCodes.includes(error)) {
          throw new Error(`Invalid Signature-Error code: ${error}`);
        }
        const result = { error };
        const algMatch = trimmed.match(/supported_algorithms=\(([^)]*)\)/);
        if (algMatch) {
          result.supported_algorithms = algMatch[1].split(/\s+/).map((a) => a.replace(/"/g, "")).filter((a) => a);
        }
        const inputMatch = trimmed.match(/required_input=\(([^)]*)\)/);
        if (inputMatch) {
          result.required_input = inputMatch[1].split(/\s+/).map((c) => c.replace(/"/g, "")).filter((c) => c);
        }
        return result;
      }
      function generateAcceptSignatureHeader(params) {
        const { label = "sig", components, sigkey, alg, tag } = params;
        const componentList = components.map((c) => `"${c}"`).join(" ");
        let header = `${label}=(${componentList})`;
        if (sigkey) {
          header += `;sigkey=${sigkey}`;
        }
        if (alg) {
          header += `;alg="${alg}"`;
        }
        if (tag) {
          header += `;tag="${tag}"`;
        }
        return header;
      }
      function parseAcceptSignature(header) {
        const trimmed = header.trim();
        const match = trimmed.match(/^([\w-]+)=\(([^)]*)\)(.*)$/);
        if (!match) {
          throw new Error("Invalid Accept-Signature format");
        }
        const label = match[1];
        const componentsStr = match[2];
        const paramsStr = match[3];
        const components = componentsStr.split(/\s+/).map((c) => c.replace(/"/g, "")).filter((c) => c);
        const result = { label, components };
        if (paramsStr) {
          const sigkeyMatch = paramsStr.match(/;sigkey=([\w]+)/);
          if (sigkeyMatch) {
            const value = sigkeyMatch[1];
            if (["jkt", "uri", "x509"].includes(value)) {
              result.sigkey = value;
            }
          }
          const algMatch = paramsStr.match(/;alg="([^"]*)"/);
          if (algMatch) {
            result.alg = algMatch[1];
          }
          const tagMatch = paramsStr.match(/;tag="([^"]*)"/);
          if (tagMatch) {
            result.tag = tagMatch[1];
          }
        }
        return result;
      }
      function parseSignature(header) {
        const results = /* @__PURE__ */ new Map();
        const entries = header.split(/,(?=\s*\w+=)/);
        for (const entry of entries) {
          const trimmed = entry.trim();
          const match = trimmed.match(/^([^=]+)=:([^:]+):$/);
          if (!match) {
            throw new Error(`Invalid Signature format: ${trimmed}`);
          }
          const label = match[1].trim();
          const base64 = match[2];
          const signature = Buffer.from(base64, "base64");
          results.set(label, new Uint8Array(signature));
        }
        return results;
      }
    }
  });

  // node_modules/@hellocoop/httpsig/dist/fetch.js
  var require_fetch = __commonJS({
    "node_modules/@hellocoop/httpsig/dist/fetch.js"(exports) {
      "use strict";
      Object.defineProperty(exports, "__esModule", { value: true });
      exports.fetch = fetch2;
      var types_js_1 = require_types();
      var crypto_js_1 = require_crypto();
      var signature_js_1 = require_signature();
      function getContentTypeFromBody(body) {
        if (body === null || body === void 0) {
          return null;
        }
        if (body instanceof URLSearchParams) {
          return "application/x-www-form-urlencoded;charset=UTF-8";
        }
        if (typeof FormData !== "undefined" && body instanceof FormData) {
          return null;
        }
        if (typeof Blob !== "undefined" && body instanceof Blob) {
          return body.type || "application/octet-stream";
        }
        if (typeof body === "string") {
          return "text/plain;charset=UTF-8";
        }
        return "application/octet-stream";
      }
      function validateComponents(components, headers) {
        for (const component of components) {
          if (component === "@signature-params" || component === "signature-key" || component === "signature-input" || component === "signature") {
            continue;
          }
          if (component.startsWith("@")) {
            if (!types_js_1.VALID_DERIVED_COMPONENTS.includes(component)) {
              throw new Error(`Invalid derived component: ${component}`);
            }
          } else {
            if (!headers.has(component)) {
              throw new Error(`Component "${component}" specified but header not found in request`);
            }
          }
        }
      }
      async function fetch2(url, options) {
        const { signingKey, signingCryptoKey, signatureKey, label = "sig", components: customComponents, dryRun = false, method = "GET", headers: inputHeaders = {}, body, ...fetchOptions } = options;
        (0, crypto_js_1.validateJwk)(signingKey);
        let privateKey;
        let algorithm;
        if (signingKey.d) {
          privateKey = await (0, crypto_js_1.importPrivateKey)(signingKey);
          algorithm = (0, crypto_js_1.getAlgorithmFromJwk)(signingKey);
        } else {
          if (!signingCryptoKey) {
            throw new Error("signingCryptoKey is required when signingKey does not contain private key material");
          }
          privateKey = signingCryptoKey;
          algorithm = (0, crypto_js_1.getAlgorithmFromJwk)(signingKey);
        }
        const publicJwk = (0, crypto_js_1.getPublicJwk)(signingKey);
        const urlObj = typeof url === "string" ? new URL(url) : url;
        const targetUri = urlObj.href;
        const headers = new Headers(inputHeaders);
        let components;
        if (customComponents) {
          components = [...new Set(customComponents)];
        } else {
          const hasBody = body !== void 0 && body !== null;
          components = hasBody ? [...types_js_1.DEFAULT_COMPONENTS_BODY] : [...types_js_1.DEFAULT_COMPONENTS_GET];
        }
        const componentValues = /* @__PURE__ */ new Map();
        if (body !== void 0 && body !== null) {
          if (!headers.has("content-type")) {
            const autoContentType = getContentTypeFromBody(body);
            if (autoContentType !== null) {
              headers.set("content-type", autoContentType);
            }
          }
          if (components.includes("content-digest")) {
            const contentDigest = await (0, signature_js_1.generateContentDigest)(body);
            headers.set("content-digest", contentDigest);
          }
        }
        if (components.includes("signature-key")) {
          const signatureKeyHeader = (0, signature_js_1.generateSignatureKeyHeader)(label, signatureKey, publicJwk);
          headers.set("signature-key", signatureKeyHeader);
        }
        validateComponents(components, headers);
        for (const component of components) {
          if (component.startsWith("@")) {
            switch (component) {
              case "@method":
                componentValues.set("@method", method.toUpperCase());
                break;
              case "@target-uri":
                componentValues.set("@target-uri", targetUri);
                break;
              case "@authority":
                componentValues.set("@authority", urlObj.host);
                break;
              case "@scheme":
                componentValues.set("@scheme", urlObj.protocol.replace(":", ""));
                break;
              case "@request-target":
                componentValues.set("@request-target", `${urlObj.pathname}${urlObj.search}`);
                break;
              case "@path":
                componentValues.set("@path", urlObj.pathname);
                break;
              case "@query":
                componentValues.set("@query", urlObj.search ? urlObj.search.substring(1) : "");
                break;
              default:
                throw new Error(`Unsupported derived component: ${component}`);
            }
          } else {
            const value = headers.get(component);
            if (value !== null) {
              componentValues.set(component, value);
            }
          }
        }
        const created = Math.floor(Date.now() / 1e3);
        const signatureInputHeader = (0, signature_js_1.generateSignatureInputHeader)(label, components, created);
        headers.set("signature-input", signatureInputHeader);
        const componentList = components.map((c) => `"${c}"`).join(" ");
        const signatureParams = `(${componentList});created=${created}`;
        componentValues.set("@signature-params", signatureParams);
        components.push("@signature-params");
        const signatureBase = (0, signature_js_1.generateSignatureBase)(components, componentValues);
        const signatureBaseBytes = new TextEncoder().encode(signatureBase);
        const signature = await (0, crypto_js_1.sign)(signatureBaseBytes, privateKey, algorithm);
        const signatureHeader = (0, signature_js_1.generateSignatureHeader)(label, signature);
        headers.set("signature", signatureHeader);
        if (dryRun) {
          return { headers };
        }
        return globalThis.fetch(urlObj, {
          ...fetchOptions,
          method,
          headers,
          body
        });
      }
    }
  });

  // node_modules/@hellocoop/httpsig/dist/utils/thumbprint.js
  var require_thumbprint = __commonJS({
    "node_modules/@hellocoop/httpsig/dist/utils/thumbprint.js"(exports) {
      "use strict";
      Object.defineProperty(exports, "__esModule", { value: true });
      exports.calculateThumbprint = calculateThumbprint;
      var base64_js_1 = require_base64();
      async function calculateThumbprint(jwk, hashAlgorithm = "SHA-256") {
        let canonical;
        switch (jwk.kty) {
          case "OKP": {
            if (!jwk.crv || !jwk.x) {
              throw new Error("OKP key missing required fields (crv, x)");
            }
            canonical = JSON.stringify({
              crv: jwk.crv,
              kty: jwk.kty,
              x: jwk.x
            });
            break;
          }
          case "EC": {
            if (!jwk.crv || !jwk.x || !jwk.y) {
              throw new Error("EC key missing required fields (crv, x, y)");
            }
            canonical = JSON.stringify({
              crv: jwk.crv,
              kty: jwk.kty,
              x: jwk.x,
              y: jwk.y
            });
            break;
          }
          default:
            throw new Error(`Unsupported key type: ${jwk.kty}`);
        }
        const hashFn = hashAlgorithm === "SHA-512" ? base64_js_1.sha512 : base64_js_1.sha256;
        const hash = await hashFn(canonical);
        return (0, base64_js_1.base64urlEncode)(hash);
      }
    }
  });

  // node_modules/@hellocoop/httpsig/dist/verify.js
  var require_verify = __commonJS({
    "node_modules/@hellocoop/httpsig/dist/verify.js"(exports) {
      "use strict";
      var __createBinding = exports && exports.__createBinding || (Object.create ? (function(o, m, k, k2) {
        if (k2 === void 0) k2 = k;
        var desc = Object.getOwnPropertyDescriptor(m, k);
        if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
          desc = { enumerable: true, get: function() {
            return m[k];
          } };
        }
        Object.defineProperty(o, k2, desc);
      }) : (function(o, m, k, k2) {
        if (k2 === void 0) k2 = k;
        o[k2] = m[k];
      }));
      var __setModuleDefault = exports && exports.__setModuleDefault || (Object.create ? (function(o, v) {
        Object.defineProperty(o, "default", { enumerable: true, value: v });
      }) : function(o, v) {
        o["default"] = v;
      });
      var __importStar = exports && exports.__importStar || /* @__PURE__ */ (function() {
        var ownKeys = function(o) {
          ownKeys = Object.getOwnPropertyNames || function(o2) {
            var ar = [];
            for (var k in o2) if (Object.prototype.hasOwnProperty.call(o2, k)) ar[ar.length] = k;
            return ar;
          };
          return ownKeys(o);
        };
        return function(mod) {
          if (mod && mod.__esModule) return mod;
          var result = {};
          if (mod != null) {
            for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
          }
          __setModuleDefault(result, mod);
          return result;
        };
      })();
      Object.defineProperty(exports, "__esModule", { value: true });
      exports.verify = verify;
      var crypto_js_1 = require_crypto();
      var signature_js_1 = require_signature();
      var base64_js_1 = require_base64();
      var thumbprint_js_1 = require_thumbprint();
      var jwksCache = /* @__PURE__ */ new Map();
      function mapToSignatureError(errorMessage) {
        if (errorMessage.includes("Missing Signature-Key") || errorMessage.includes("Missing Signature-Input") || errorMessage.includes("Missing Signature") || errorMessage.includes("No signature found") || errorMessage.includes("No Signature-Input found") || errorMessage.includes("does not verify") || errorMessage.includes("Signature timestamp out of")) {
          return { error: "invalid_signature" };
        }
        if (errorMessage.includes("AAuth profile violation")) {
          return {
            error: "invalid_input",
            required_input: ["@method", "@authority", "@path", "signature-key"]
          };
        }
        if (errorMessage.includes("content-digest")) {
          return { error: "invalid_input" };
        }
        if (errorMessage.includes("Missing header for component")) {
          return { error: "invalid_input" };
        }
        if (errorMessage.includes("Unsupported signature key type") || errorMessage.includes("Unsupported Signature-Key scheme")) {
          return { error: "invalid_key" };
        }
        if (errorMessage.includes("Signature-Key") && errorMessage.includes("missing")) {
          return { error: "invalid_key" };
        }
        if (errorMessage.includes("Invalid JWK") || errorMessage.includes("validate") || errorMessage.includes("kty parameter")) {
          return { error: "invalid_key" };
        }
        if (errorMessage.includes("not found in JWKS") || errorMessage.includes("unknown_key")) {
          return { error: "unknown_key" };
        }
        if (errorMessage.includes("jkt-jwt: JWT expired")) {
          return { error: "expired_jwt" };
        }
        if (errorMessage.includes("jkt-jwt:") || errorMessage.includes("Invalid JWT") || errorMessage.includes("JWT missing")) {
          return { error: "invalid_jwt" };
        }
        return { error: "invalid_signature" };
      }
      function normalizeHeaders(headers) {
        const result = /* @__PURE__ */ new Map();
        if (headers instanceof Headers) {
          headers.forEach((value, key) => {
            result.set(key.toLowerCase(), value);
          });
        } else {
          for (const [key, value] of Object.entries(headers)) {
            const normalized = Array.isArray(value) ? value.join(", ") : value;
            result.set(key.toLowerCase(), normalized);
          }
        }
        return result;
      }
      async function fetchJWKS(url, cacheTtl) {
        const cached = jwksCache.get(url);
        if (cached && cached.expiresAt > Date.now()) {
          return cached.jwks;
        }
        const response = await globalThis.fetch(url);
        if (!response.ok) {
          throw new Error(`Failed to fetch JWKS from ${url}: ${response.statusText}`);
        }
        const jwks = await response.json();
        jwksCache.set(url, {
          jwks,
          expiresAt: Date.now() + cacheTtl
        });
        return jwks;
      }
      async function getPublicKeyFromJWKS(id, kid, dwk, cacheTtl) {
        const metadataUrl = `${id}/.well-known/${dwk}`;
        const metadata = await fetchJWKS(metadataUrl, cacheTtl);
        if (!metadata.jwks_uri) {
          throw new Error(`Metadata document missing jwks_uri: ${metadataUrl}`);
        }
        const jwksUrl = metadata.jwks_uri;
        const jwks = await fetchJWKS(jwksUrl, cacheTtl);
        if (!jwks.keys || !Array.isArray(jwks.keys)) {
          throw new Error(`Invalid JWKS format from ${jwksUrl}`);
        }
        const key = jwks.keys.find((k) => k.kid === kid);
        if (!key) {
          throw new Error(`Key with kid="${kid}" not found in JWKS from ${jwksUrl}`);
        }
        return key;
      }
      function decodeJWT(jwt) {
        const parts = jwt.split(".");
        if (parts.length !== 3) {
          throw new Error("Invalid JWT format");
        }
        const header = JSON.parse(new TextDecoder().decode((0, base64_js_1.base64urlDecode)(parts[0])));
        const payload = JSON.parse(new TextDecoder().decode((0, base64_js_1.base64urlDecode)(parts[1])));
        if (!payload.cnf || !payload.cnf.jwk) {
          throw new Error("JWT missing cnf.jwk claim");
        }
        return {
          header,
          payload,
          publicKey: payload.cnf.jwk
        };
      }
      var JKT_JWT_TYPES = {
        "jkt-s256+jwt": {
          hashAlgorithm: "SHA-256",
          issPrefix: "urn:jkt:sha-256:"
        },
        "jkt-s512+jwt": {
          hashAlgorithm: "SHA-512",
          issPrefix: "urn:jkt:sha-512:"
        }
      };
      async function verifyJktJwt(jwtString, maxClockSkew) {
        const parts = jwtString.split(".");
        if (parts.length !== 3) {
          throw new Error("Invalid JWT format");
        }
        const header = JSON.parse(new TextDecoder().decode((0, base64_js_1.base64urlDecode)(parts[0])));
        const payload = JSON.parse(new TextDecoder().decode((0, base64_js_1.base64urlDecode)(parts[1])));
        const typConfig = JKT_JWT_TYPES[header.typ];
        if (!typConfig) {
          throw new Error(`Unsupported jkt-jwt typ: ${header.typ}. Supported: ${Object.keys(JKT_JWT_TYPES).join(", ")}`);
        }
        const identityJwk = header.jwk;
        if (!identityJwk) {
          throw new Error("jkt-jwt: JWT header missing jwk claim");
        }
        const thumbprint = await (0, thumbprint_js_1.calculateThumbprint)(identityJwk, typConfig.hashAlgorithm);
        const expectedIss = `${typConfig.issPrefix}${thumbprint}`;
        if (payload.iss !== expectedIss) {
          throw new Error(`jkt-jwt: iss mismatch. Expected ${expectedIss}, got ${payload.iss}`);
        }
        (0, crypto_js_1.validateJwk)(identityJwk);
        const identityPublicKey = await (0, crypto_js_1.importPublicKey)(identityJwk);
        const algorithm = (0, crypto_js_1.getAlgorithmFromJwk)(identityJwk);
        const signedData = new TextEncoder().encode(`${parts[0]}.${parts[1]}`);
        const signature = (0, base64_js_1.base64urlDecode)(parts[2]);
        const jwtValid = await (0, crypto_js_1.verify)(signedData, signature, identityPublicKey, algorithm);
        if (!jwtValid) {
          throw new Error("jkt-jwt: JWT signature verification failed");
        }
        const now = Math.floor(Date.now() / 1e3);
        if (!payload.exp || typeof payload.exp !== "number") {
          throw new Error("jkt-jwt: JWT missing exp claim");
        }
        if (payload.exp + maxClockSkew < now) {
          throw new Error("jkt-jwt: JWT expired");
        }
        if (!payload.iat || typeof payload.iat !== "number") {
          throw new Error("jkt-jwt: JWT missing iat claim");
        }
        if (payload.iat - maxClockSkew > now) {
          throw new Error("jkt-jwt: JWT iat is in the future");
        }
        if (!payload.cnf || !payload.cnf.jwk) {
          throw new Error("jkt-jwt: JWT missing cnf.jwk claim");
        }
        return {
          header,
          payload,
          ephemeralKey: payload.cnf.jwk,
          identityKey: identityJwk,
          identityThumbprint: expectedIss
        };
      }
      async function verify(request, options = {}) {
        const {
          maxClockSkew = 60,
          jwksCacheTtl = 36e5,
          // 1 hour
          strictAAuth = true
          // Enforce AAuth profile by default
        } = options;
        try {
          const headers = normalizeHeaders(request.headers);
          const signatureKeyHeader = headers.get("signature-key");
          if (!signatureKeyHeader) {
            throw new Error("Missing Signature-Key header");
          }
          const signatureKeys = (0, signature_js_1.parseSignatureKey)(signatureKeyHeader);
          const signatureKey = signatureKeys[0];
          const label = signatureKey.label;
          const signatureInputHeader = headers.get("signature-input");
          if (!signatureInputHeader) {
            throw new Error("Missing Signature-Input header");
          }
          const signatureInputs = (0, signature_js_1.parseSignatureInput)(signatureInputHeader);
          const signatureInput = signatureInputs.find((si) => si.label === label);
          if (!signatureInput) {
            throw new Error(`No Signature-Input found for label "${label}" from Signature-Key`);
          }
          const { components, params } = signatureInput;
          if (strictAAuth && !components.includes("signature-key")) {
            throw new Error("AAuth profile violation: signature-key must be in covered components");
          }
          const now = Math.floor(Date.now() / 1e3);
          const skew = Math.abs(now - params.created);
          if (skew > maxClockSkew) {
            throw new Error(`Signature timestamp out of acceptable range (skew: ${skew}s)`);
          }
          let publicJwk;
          let jwtData;
          let jktJwtData;
          let jwksUriData;
          if (signatureKey.type === "hwk") {
            publicJwk = signatureKey.value;
          } else if (signatureKey.type === "jwt") {
            const jwtValue = signatureKey.value;
            const { header, payload, publicKey: publicKey2 } = decodeJWT(jwtValue.jwt);
            publicJwk = publicKey2;
            jwtData = {
              header,
              payload,
              raw: jwtValue.jwt
            };
          } else if (signatureKey.type === "jkt_jwt") {
            const jwtValue = signatureKey.value;
            const { header, payload, ephemeralKey, identityKey, identityThumbprint } = await verifyJktJwt(jwtValue.jwt, maxClockSkew);
            publicJwk = ephemeralKey;
            jktJwtData = {
              header,
              payload,
              raw: jwtValue.jwt,
              identityKey,
              identityThumbprint
            };
          } else if (signatureKey.type === "jwks_uri") {
            const jwksUriValue = signatureKey.value;
            const { id, kid, dwk } = jwksUriValue;
            publicJwk = await getPublicKeyFromJWKS(id, kid, dwk, jwksCacheTtl);
            jwksUriData = { id, kid, dwk };
          } else {
            throw new Error(`Unsupported signature key type: ${signatureKey.type}`);
          }
          (0, crypto_js_1.validateJwk)(publicJwk);
          const signatureHeader = headers.get("signature");
          if (!signatureHeader) {
            throw new Error("Missing Signature header");
          }
          const signatures = (0, signature_js_1.parseSignature)(signatureHeader);
          const signature = signatures.get(label);
          if (!signature) {
            throw new Error(`No signature found for label: ${label}`);
          }
          const queryString = request.query ? `?${request.query}` : "";
          const targetUri = `https://${request.authority}${request.path}${queryString}`;
          const componentValues = /* @__PURE__ */ new Map();
          componentValues.set("@method", request.method.toUpperCase());
          componentValues.set("@target-uri", targetUri);
          componentValues.set("@authority", request.authority);
          componentValues.set("@scheme", "https");
          componentValues.set("@request-target", `${request.path}${queryString}`);
          componentValues.set("@path", request.path);
          componentValues.set("@query", request.query || "");
          if (request.body !== void 0 && components.includes("content-digest")) {
            const expectedDigest = headers.get("content-digest");
            if (!expectedDigest) {
              throw new Error("content-digest component specified but header missing");
            }
            const { generateContentDigest } = await Promise.resolve().then(() => __importStar(require_signature()));
            const actualDigest = await generateContentDigest(request.body);
            if (actualDigest !== expectedDigest) {
              throw new Error("content-digest does not match body");
            }
          }
          for (const component of components) {
            if (component.startsWith("@")) {
              continue;
            }
            const value = headers.get(component);
            if (value === void 0) {
              throw new Error(`Missing header for component: ${component}`);
            }
            componentValues.set(component, value);
          }
          const componentList = components.map((c) => `"${c}"`).join(" ");
          const paramPairs = Object.entries(params).map(([key, value]) => {
            if (typeof value === "number") {
              return `${key}=${value}`;
            }
            const stringValue = String(value);
            if (stringValue.startsWith('"') && stringValue.endsWith('"')) {
              return `${key}=${stringValue}`;
            }
            return `${key}="${stringValue}"`;
          }).join(";");
          const signatureParams = `(${componentList});${paramPairs}`;
          componentValues.set("@signature-params", signatureParams);
          const componentsWithParams = [...components, "@signature-params"];
          const signatureBase = (0, signature_js_1.generateSignatureBase)(componentsWithParams, componentValues);
          const signatureBaseBytes = new TextEncoder().encode(signatureBase);
          const thumbprint = await (0, thumbprint_js_1.calculateThumbprint)(publicJwk);
          const publicKey = await (0, crypto_js_1.importPublicKey)(publicJwk);
          const algorithm = (0, crypto_js_1.getAlgorithmFromJwk)(publicJwk);
          const isValid = await (0, crypto_js_1.verify)(signatureBaseBytes, signature, publicKey, algorithm);
          const result = {
            verified: isValid,
            label,
            keyType: signatureKey.type,
            publicKey: publicJwk,
            thumbprint,
            created: params.created
          };
          if (jwtData) {
            result.jwt = jwtData;
          }
          if (jktJwtData) {
            result.jkt_jwt = jktJwtData;
          }
          if (jwksUriData) {
            result.jwks_uri = jwksUriData;
          }
          return result;
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          return {
            verified: false,
            label: "",
            keyType: "hwk",
            publicKey: {},
            thumbprint: "",
            created: 0,
            error: errorMessage,
            signatureError: mapToSignatureError(errorMessage)
          };
        }
      }
    }
  });

  // node_modules/@hellocoop/httpsig/dist/helpers.js
  var require_helpers = __commonJS({
    "node_modules/@hellocoop/httpsig/dist/helpers.js"(exports) {
      "use strict";
      Object.defineProperty(exports, "__esModule", { value: true });
      exports.expressVerify = expressVerify;
      exports.fastifyVerify = fastifyVerify;
      exports.nextJsVerify = nextJsVerify;
      exports.nextJsPagesVerify = nextJsPagesVerify;
      var verify_js_1 = require_verify();
      async function expressVerify(req, authority, options) {
        const urlObj = new URL(req.originalUrl, `${req.protocol}://${req.hostname}`);
        return (0, verify_js_1.verify)({
          method: req.method,
          authority,
          path: urlObj.pathname,
          query: urlObj.search ? urlObj.search.substring(1) : void 0,
          headers: req.headers,
          body: req.body
        }, options);
      }
      async function fastifyVerify(request, authority, options) {
        const urlObj = new URL(request.url, `${request.protocol}://${request.hostname}`);
        return (0, verify_js_1.verify)({
          method: request.method,
          authority,
          path: urlObj.pathname,
          query: urlObj.search ? urlObj.search.substring(1) : void 0,
          headers: request.headers,
          body: request.rawBody
        }, options);
      }
      async function nextJsVerify(request, authority, body, options) {
        const urlObj = new URL(request.url);
        return (0, verify_js_1.verify)({
          method: request.method,
          authority,
          path: urlObj.pathname,
          query: urlObj.search ? urlObj.search.substring(1) : void 0,
          headers: request.headers,
          body
        }, options);
      }
      async function nextJsPagesVerify(req, authority, body, options) {
        const reqUrl = req.url || "/";
        const urlObj = new URL(reqUrl, `https://${authority}`);
        return (0, verify_js_1.verify)({
          method: req.method || "GET",
          authority,
          path: urlObj.pathname,
          query: urlObj.search ? urlObj.search.substring(1) : void 0,
          headers: req.headers,
          body
        }, options);
      }
    }
  });

  // node_modules/@hellocoop/httpsig/dist/index.js
  var require_dist = __commonJS({
    "node_modules/@hellocoop/httpsig/dist/index.js"(exports) {
      "use strict";
      Object.defineProperty(exports, "__esModule", { value: true });
      exports.DEFAULT_COMPONENTS_BODY = exports.DEFAULT_COMPONENTS_GET = exports.VALID_DERIVED_COMPONENTS = exports.generateKeyPair = exports.parseAcceptSignature = exports.generateAcceptSignatureHeader = exports.parseSignatureError = exports.generateSignatureErrorHeader = exports.nextJsPagesVerify = exports.nextJsVerify = exports.fastifyVerify = exports.expressVerify = exports.verify = void 0;
      var fetch_js_1 = require_fetch();
      Object.defineProperty(exports, "fetch", { enumerable: true, get: function() {
        return fetch_js_1.fetch;
      } });
      var verify_js_1 = require_verify();
      Object.defineProperty(exports, "verify", { enumerable: true, get: function() {
        return verify_js_1.verify;
      } });
      var helpers_js_1 = require_helpers();
      Object.defineProperty(exports, "expressVerify", { enumerable: true, get: function() {
        return helpers_js_1.expressVerify;
      } });
      Object.defineProperty(exports, "fastifyVerify", { enumerable: true, get: function() {
        return helpers_js_1.fastifyVerify;
      } });
      Object.defineProperty(exports, "nextJsVerify", { enumerable: true, get: function() {
        return helpers_js_1.nextJsVerify;
      } });
      Object.defineProperty(exports, "nextJsPagesVerify", { enumerable: true, get: function() {
        return helpers_js_1.nextJsPagesVerify;
      } });
      var signature_js_1 = require_signature();
      Object.defineProperty(exports, "generateSignatureErrorHeader", { enumerable: true, get: function() {
        return signature_js_1.generateSignatureErrorHeader;
      } });
      Object.defineProperty(exports, "parseSignatureError", { enumerable: true, get: function() {
        return signature_js_1.parseSignatureError;
      } });
      Object.defineProperty(exports, "generateAcceptSignatureHeader", { enumerable: true, get: function() {
        return signature_js_1.generateAcceptSignatureHeader;
      } });
      Object.defineProperty(exports, "parseAcceptSignature", { enumerable: true, get: function() {
        return signature_js_1.parseAcceptSignature;
      } });
      var crypto_js_1 = require_crypto();
      Object.defineProperty(exports, "generateKeyPair", { enumerable: true, get: function() {
        return crypto_js_1.generateKeyPair;
      } });
      var types_js_1 = require_types();
      Object.defineProperty(exports, "VALID_DERIVED_COMPONENTS", { enumerable: true, get: function() {
        return types_js_1.VALID_DERIVED_COMPONENTS;
      } });
      Object.defineProperty(exports, "DEFAULT_COMPONENTS_GET", { enumerable: true, get: function() {
        return types_js_1.DEFAULT_COMPONENTS_GET;
      } });
      Object.defineProperty(exports, "DEFAULT_COMPONENTS_BODY", { enumerable: true, get: function() {
        return types_js_1.DEFAULT_COMPONENTS_BODY;
      } });
    }
  });

  // client/protocol.js
  var import_httpsig = __toESM(require_dist());
  function clearLog() {
    document.getElementById("protocol-log").innerHTML = "";
    document.getElementById("log-section").classList.add("hidden");
  }
  function showLog() {
    document.getElementById("log-section").classList.remove("hidden");
  }
  function addLogStep(label, status, content) {
    const log = document.getElementById("protocol-log");
    const step = document.createElement("details");
    step.className = `log-step ${status}`;
    step.open = true;
    const summary = document.createElement("summary");
    const indicator = status === "success" ? "\u2713" : status === "pending" ? "\u2026" : "\u2717";
    summary.innerHTML = `<span class="step-label">${indicator} ${label}</span>`;
    step.appendChild(summary);
    const body = document.createElement("div");
    body.style.marginTop = "0.5rem";
    body.innerHTML = content;
    step.appendChild(body);
    log.appendChild(step);
    step.scrollIntoView({ behavior: "smooth", block: "nearest" });
    return step;
  }
  function formatRequest(method, url, headers, body) {
    let html = `<div class="token-display">${escapeHtml(method)} ${escapeHtml(url)}
`;
    if (headers) {
      for (const [k, v] of Object.entries(headers)) {
        html += `${escapeHtml(k)}: ${escapeHtml(v)}
`;
      }
    }
    if (body) {
      html += `
${renderJSON(body)}`;
    }
    html += "</div>";
    return html;
  }
  function formatResponse(status, headers, body) {
    let html = `<div class="token-display">HTTP ${status}
`;
    if (headers) {
      for (const [k, v] of Object.entries(headers)) {
        html += `${escapeHtml(k)}: ${escapeHtml(v)}
`;
      }
    }
    if (body) {
      html += `
${renderJSON(body)}`;
    }
    html += "</div>";
    return html;
  }
  function formatToken(label, token, decoded) {
    return `
    <details>
      <summary class="detail-summary">${escapeHtml(label)}</summary>
      <div class="token-display encoded">${renderEncodedJWT(token)}</div>
    </details>
    <details open>
      <summary class="detail-summary">Decoded</summary>
      <div class="token-display">${renderJSON(decoded)}</div>
    </details>
  `;
  }
  function getSelectedScopes() {
    const checkboxes = document.querySelectorAll('#authz-section input[type="checkbox"]:checked');
    return Array.from(checkboxes).map((cb) => cb.value).join(" ");
  }
  function getHints() {
    const hints = {};
    const fields = ["login-hint", "domain-hint", "provider-hint", "tenant"];
    for (const field of fields) {
      const val = document.getElementById(field)?.value?.trim();
      if (val) {
        hints[field.replace("-", "_")] = val;
      }
    }
    return hints;
  }
  async function startAuthorization() {
    const psUrl = (window.getCurrentPS?.() || "").trim();
    if (!psUrl) {
      alert("Please choose or enter a Person Server URL");
      return;
    }
    clearLog();
    showLog();
    const scope = getSelectedScopes();
    if (!scope) {
      addLogStep("Error", "error", "<p>No scopes selected</p>");
      return;
    }
    const hints = getHints();
    addLogStep(
      "Requesting authorization...",
      "pending",
      formatRequest("POST", "/authorize", { "Content-Type": "application/json" }, {
        ps: psUrl,
        scope,
        agent_token: "(agent token)"
      })
    );
    let authzData;
    try {
      const res = await fetch("/authorize", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Session-Id": sessionId
        },
        body: JSON.stringify({ ps: psUrl, scope, agent_token: agentToken })
      });
      authzData = await res.json();
      if (!res.ok) {
        document.getElementById("protocol-log").lastChild.remove();
        addLogStep(
          "Authorization request failed",
          "error",
          `<p style="color: var(--error)">${escapeHtml(authzData.error || "Unknown error")}</p>` + (authzData.ps_metadata_url ? `<p>Tried: ${escapeHtml(authzData.ps_metadata_url)}</p>` : "")
        );
        return;
      }
    } catch (err) {
      document.getElementById("protocol-log").lastChild.remove();
      addLogStep(
        "Network error",
        "error",
        `<p style="color: var(--error)">${escapeHtml(err.message)}</p>`
      );
      return;
    }
    document.getElementById("protocol-log").lastChild.remove();
    addLogStep(
      "Discover Person Server",
      "success",
      formatRequest("GET", authzData.ps_metadata_url, null, null) + '<label style="margin-top: 0.5rem;">Response</label>' + formatResponse(200, null, authzData.ps_metadata)
    );
    addLogStep(
      "Resource Token Created",
      "success",
      formatToken("Resource Token (aa-resource+jwt)", authzData.resource_token, authzData.resource_token_decoded)
    );
    const tokenEndpoint = authzData.ps_metadata.token_endpoint;
    const psRequestBody = { resource_token: authzData.resource_token, ...hints };
    const capabilities = "interaction";
    addLogStep(
      "Calling Person Server...",
      "pending",
      formatRequest("POST", tokenEndpoint, {
        "Content-Type": "application/json",
        "AAuth-Capabilities": capabilities,
        "Signature-Input": 'sig=("@method" "@authority" "@path" "signature-key");created=...',
        "Signature": "sig=:...:",
        "Signature-Key": `sig=jwt;jwt="${agentToken?.substring(0, 20)}..."`
      }, psRequestBody)
    );
    try {
      const signingJwk = await crypto.subtle.exportKey("jwk", ephemeralKeyPair.publicKey);
      const psRes = await (0, import_httpsig.fetch)(tokenEndpoint, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "AAuth-Capabilities": capabilities
        },
        body: JSON.stringify(psRequestBody),
        signingKey: signingJwk,
        signingCryptoKey: ephemeralKeyPair.privateKey,
        signatureKey: { type: "jwt", jwt: agentToken },
        components: ["@method", "@authority", "@path", "signature-key"]
      });
      const responseHeaders = {};
      for (const key of ["location", "retry-after", "aauth-requirement"]) {
        const val = psRes.headers.get(key);
        if (val) responseHeaders[key] = val;
      }
      let psBody;
      try {
        psBody = await psRes.json();
      } catch {
        psBody = null;
      }
      document.getElementById("protocol-log").lastChild.remove();
      if (psRes.status === 200 && psBody?.auth_token) {
        addLogStep(
          "Authorization Granted",
          "success",
          formatResponse(200, responseHeaders, psBody) + formatToken(
            "Auth Token",
            psBody.auth_token,
            decodeJWTPayloadBrowser(psBody.auth_token)
          )
        );
      } else if (psRes.status === 202) {
        const reqHeader = psRes.headers.get("aauth-requirement") || "";
        const interaction = parseInteractionHeader(reqHeader);
        const pollUrl = psRes.headers.get("location");
        addLogStep(
          "Interaction Required",
          "pending",
          formatResponse(202, responseHeaders, psBody) + renderInteraction(interaction, pollUrl)
        );
        if (pollUrl) {
          startPolling(pollUrl, tokenEndpoint);
        }
      } else {
        addLogStep(
          "Person Server Response",
          psRes.ok ? "success" : "error",
          formatResponse(psRes.status, responseHeaders, psBody)
        );
      }
    } catch (err) {
      document.getElementById("protocol-log").lastChild.remove();
      const isCors = err instanceof TypeError && err.message.includes("fetch");
      addLogStep(
        "Person Server Call Failed",
        "error",
        `<p style="color: var(--error)">${escapeHtml(err.message)}</p>` + (isCors ? '<p style="color: var(--muted); font-size: 0.85rem;">This may be a CORS issue. The Person Server must include Access-Control-Allow-Origin headers to allow browser requests.</p>' : "")
      );
    }
  }
  function parseInteractionHeader(header) {
    const result = {};
    const parts = header.split(";").map((s) => s.trim());
    for (const part of parts) {
      const eq = part.indexOf("=");
      if (eq === -1) continue;
      const key = part.substring(0, eq).trim();
      let val = part.substring(eq + 1).trim();
      if (val.startsWith('"') && val.endsWith('"')) {
        val = val.slice(1, -1);
      }
      result[key] = val;
    }
    return result;
  }
  function renderInteraction(interaction, pollUrl) {
    if (!interaction.url || !interaction.code) {
      return '<p style="color: var(--muted);">Interaction required but no URL/code provided.</p>';
    }
    const fullUrl = `${interaction.url}?code=${encodeURIComponent(interaction.code)}`;
    let html = `
    <div class="interaction-box">
      <p>The Person Server requires user interaction.</p>
      <div class="interaction-code">${escapeHtml(interaction.code)}</div>
      <div id="qr-code"></div>
      <div style="margin-top: 0.75rem;">
        <a href="${escapeHtml(fullUrl)}" target="_blank" rel="noopener">
          <button>Go to Person Server</button>
        </a>
      </div>
    </div>
  `;
    setTimeout(() => {
      const qrContainer = document.getElementById("qr-code");
      if (qrContainer && typeof qrcode !== "undefined") {
        const qr = qrcode(0, "M");
        qr.addData(fullUrl);
        qr.make();
        qrContainer.innerHTML = qr.createSvgTag(4);
      }
    }, 0);
    return html;
  }
  var pollInterval = null;
  function startPolling(pollUrl, baseUrl) {
    if (pollInterval) clearInterval(pollInterval);
    const absolutePollUrl = new URL(pollUrl, baseUrl).href;
    pollInterval = setInterval(async () => {
      try {
        const res = await fetch(absolutePollUrl);
        if (res.status === 200) {
          clearInterval(pollInterval);
          pollInterval = null;
          const body = await res.json();
          addLogStep(
            "Authorization Granted",
            "success",
            formatResponse(200, null, body) + (body.auth_token ? formatToken(
              "Auth Token",
              body.auth_token,
              decodeJWTPayloadBrowser(body.auth_token)
            ) : "")
          );
        } else if (res.status === 403) {
          clearInterval(pollInterval);
          pollInterval = null;
          addLogStep(
            "Authorization Denied",
            "error",
            formatResponse(403, null, await res.json().catch(() => null))
          );
        } else if (res.status === 408) {
          clearInterval(pollInterval);
          pollInterval = null;
          addLogStep(
            "Authorization Timed Out",
            "error",
            formatResponse(408, null, null)
          );
        }
      } catch (err) {
        console.log("Poll error:", err.message);
      }
    }, 5e3);
  }
  function decodeJWTPayloadBrowser(jwt) {
    try {
      const parts = jwt.split(".");
      return JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
    } catch {
      return null;
    }
  }
  document.getElementById("authz-btn").addEventListener("click", startAuthorization);
})();
