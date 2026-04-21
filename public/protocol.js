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
  var __copyProps = (to, from, except, desc2) => {
    if (from && typeof from === "object" || typeof from === "function") {
      for (let key of __getOwnPropNames(from))
        if (!__hasOwnProp.call(to, key) && key !== except)
          __defProp(to, key, { get: () => from[key], enumerable: !(desc2 = __getOwnPropDesc(from, key)) || desc2.enumerable });
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
        var desc2 = Object.getOwnPropertyDescriptor(m, k);
        if (!desc2 || ("get" in desc2 ? !m.__esModule : desc2.writable || desc2.configurable)) {
          desc2 = { enumerable: true, get: function() {
            return m[k];
          } };
        }
        Object.defineProperty(o, k2, desc2);
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

  // node_modules/qrcode-generator/dist/qrcode.mjs
  var qrcode = function(typeNumber, errorCorrectionLevel) {
    const PAD0 = 236;
    const PAD1 = 17;
    let _typeNumber = typeNumber;
    const _errorCorrectionLevel = QRErrorCorrectionLevel[errorCorrectionLevel];
    let _modules = null;
    let _moduleCount = 0;
    let _dataCache = null;
    const _dataList = [];
    const _this = {};
    const makeImpl = function(test, maskPattern) {
      _moduleCount = _typeNumber * 4 + 17;
      _modules = (function(moduleCount) {
        const modules = new Array(moduleCount);
        for (let row = 0; row < moduleCount; row += 1) {
          modules[row] = new Array(moduleCount);
          for (let col = 0; col < moduleCount; col += 1) {
            modules[row][col] = null;
          }
        }
        return modules;
      })(_moduleCount);
      setupPositionProbePattern(0, 0);
      setupPositionProbePattern(_moduleCount - 7, 0);
      setupPositionProbePattern(0, _moduleCount - 7);
      setupPositionAdjustPattern();
      setupTimingPattern();
      setupTypeInfo(test, maskPattern);
      if (_typeNumber >= 7) {
        setupTypeNumber(test);
      }
      if (_dataCache == null) {
        _dataCache = createData(_typeNumber, _errorCorrectionLevel, _dataList);
      }
      mapData(_dataCache, maskPattern);
    };
    const setupPositionProbePattern = function(row, col) {
      for (let r = -1; r <= 7; r += 1) {
        if (row + r <= -1 || _moduleCount <= row + r) continue;
        for (let c = -1; c <= 7; c += 1) {
          if (col + c <= -1 || _moduleCount <= col + c) continue;
          if (0 <= r && r <= 6 && (c == 0 || c == 6) || 0 <= c && c <= 6 && (r == 0 || r == 6) || 2 <= r && r <= 4 && 2 <= c && c <= 4) {
            _modules[row + r][col + c] = true;
          } else {
            _modules[row + r][col + c] = false;
          }
        }
      }
    };
    const getBestMaskPattern = function() {
      let minLostPoint = 0;
      let pattern = 0;
      for (let i = 0; i < 8; i += 1) {
        makeImpl(true, i);
        const lostPoint = QRUtil.getLostPoint(_this);
        if (i == 0 || minLostPoint > lostPoint) {
          minLostPoint = lostPoint;
          pattern = i;
        }
      }
      return pattern;
    };
    const setupTimingPattern = function() {
      for (let r = 8; r < _moduleCount - 8; r += 1) {
        if (_modules[r][6] != null) {
          continue;
        }
        _modules[r][6] = r % 2 == 0;
      }
      for (let c = 8; c < _moduleCount - 8; c += 1) {
        if (_modules[6][c] != null) {
          continue;
        }
        _modules[6][c] = c % 2 == 0;
      }
    };
    const setupPositionAdjustPattern = function() {
      const pos = QRUtil.getPatternPosition(_typeNumber);
      for (let i = 0; i < pos.length; i += 1) {
        for (let j = 0; j < pos.length; j += 1) {
          const row = pos[i];
          const col = pos[j];
          if (_modules[row][col] != null) {
            continue;
          }
          for (let r = -2; r <= 2; r += 1) {
            for (let c = -2; c <= 2; c += 1) {
              if (r == -2 || r == 2 || c == -2 || c == 2 || r == 0 && c == 0) {
                _modules[row + r][col + c] = true;
              } else {
                _modules[row + r][col + c] = false;
              }
            }
          }
        }
      }
    };
    const setupTypeNumber = function(test) {
      const bits = QRUtil.getBCHTypeNumber(_typeNumber);
      for (let i = 0; i < 18; i += 1) {
        const mod = !test && (bits >> i & 1) == 1;
        _modules[Math.floor(i / 3)][i % 3 + _moduleCount - 8 - 3] = mod;
      }
      for (let i = 0; i < 18; i += 1) {
        const mod = !test && (bits >> i & 1) == 1;
        _modules[i % 3 + _moduleCount - 8 - 3][Math.floor(i / 3)] = mod;
      }
    };
    const setupTypeInfo = function(test, maskPattern) {
      const data = _errorCorrectionLevel << 3 | maskPattern;
      const bits = QRUtil.getBCHTypeInfo(data);
      for (let i = 0; i < 15; i += 1) {
        const mod = !test && (bits >> i & 1) == 1;
        if (i < 6) {
          _modules[i][8] = mod;
        } else if (i < 8) {
          _modules[i + 1][8] = mod;
        } else {
          _modules[_moduleCount - 15 + i][8] = mod;
        }
      }
      for (let i = 0; i < 15; i += 1) {
        const mod = !test && (bits >> i & 1) == 1;
        if (i < 8) {
          _modules[8][_moduleCount - i - 1] = mod;
        } else if (i < 9) {
          _modules[8][15 - i - 1 + 1] = mod;
        } else {
          _modules[8][15 - i - 1] = mod;
        }
      }
      _modules[_moduleCount - 8][8] = !test;
    };
    const mapData = function(data, maskPattern) {
      let inc = -1;
      let row = _moduleCount - 1;
      let bitIndex = 7;
      let byteIndex = 0;
      const maskFunc = QRUtil.getMaskFunction(maskPattern);
      for (let col = _moduleCount - 1; col > 0; col -= 2) {
        if (col == 6) col -= 1;
        while (true) {
          for (let c = 0; c < 2; c += 1) {
            if (_modules[row][col - c] == null) {
              let dark = false;
              if (byteIndex < data.length) {
                dark = (data[byteIndex] >>> bitIndex & 1) == 1;
              }
              const mask = maskFunc(row, col - c);
              if (mask) {
                dark = !dark;
              }
              _modules[row][col - c] = dark;
              bitIndex -= 1;
              if (bitIndex == -1) {
                byteIndex += 1;
                bitIndex = 7;
              }
            }
          }
          row += inc;
          if (row < 0 || _moduleCount <= row) {
            row -= inc;
            inc = -inc;
            break;
          }
        }
      }
    };
    const createBytes = function(buffer, rsBlocks) {
      let offset = 0;
      let maxDcCount = 0;
      let maxEcCount = 0;
      const dcdata = new Array(rsBlocks.length);
      const ecdata = new Array(rsBlocks.length);
      for (let r = 0; r < rsBlocks.length; r += 1) {
        const dcCount = rsBlocks[r].dataCount;
        const ecCount = rsBlocks[r].totalCount - dcCount;
        maxDcCount = Math.max(maxDcCount, dcCount);
        maxEcCount = Math.max(maxEcCount, ecCount);
        dcdata[r] = new Array(dcCount);
        for (let i = 0; i < dcdata[r].length; i += 1) {
          dcdata[r][i] = 255 & buffer.getBuffer()[i + offset];
        }
        offset += dcCount;
        const rsPoly = QRUtil.getErrorCorrectPolynomial(ecCount);
        const rawPoly = qrPolynomial(dcdata[r], rsPoly.getLength() - 1);
        const modPoly = rawPoly.mod(rsPoly);
        ecdata[r] = new Array(rsPoly.getLength() - 1);
        for (let i = 0; i < ecdata[r].length; i += 1) {
          const modIndex = i + modPoly.getLength() - ecdata[r].length;
          ecdata[r][i] = modIndex >= 0 ? modPoly.getAt(modIndex) : 0;
        }
      }
      let totalCodeCount = 0;
      for (let i = 0; i < rsBlocks.length; i += 1) {
        totalCodeCount += rsBlocks[i].totalCount;
      }
      const data = new Array(totalCodeCount);
      let index = 0;
      for (let i = 0; i < maxDcCount; i += 1) {
        for (let r = 0; r < rsBlocks.length; r += 1) {
          if (i < dcdata[r].length) {
            data[index] = dcdata[r][i];
            index += 1;
          }
        }
      }
      for (let i = 0; i < maxEcCount; i += 1) {
        for (let r = 0; r < rsBlocks.length; r += 1) {
          if (i < ecdata[r].length) {
            data[index] = ecdata[r][i];
            index += 1;
          }
        }
      }
      return data;
    };
    const createData = function(typeNumber2, errorCorrectionLevel2, dataList) {
      const rsBlocks = QRRSBlock.getRSBlocks(typeNumber2, errorCorrectionLevel2);
      const buffer = qrBitBuffer();
      for (let i = 0; i < dataList.length; i += 1) {
        const data = dataList[i];
        buffer.put(data.getMode(), 4);
        buffer.put(data.getLength(), QRUtil.getLengthInBits(data.getMode(), typeNumber2));
        data.write(buffer);
      }
      let totalDataCount = 0;
      for (let i = 0; i < rsBlocks.length; i += 1) {
        totalDataCount += rsBlocks[i].dataCount;
      }
      if (buffer.getLengthInBits() > totalDataCount * 8) {
        throw "code length overflow. (" + buffer.getLengthInBits() + ">" + totalDataCount * 8 + ")";
      }
      if (buffer.getLengthInBits() + 4 <= totalDataCount * 8) {
        buffer.put(0, 4);
      }
      while (buffer.getLengthInBits() % 8 != 0) {
        buffer.putBit(false);
      }
      while (true) {
        if (buffer.getLengthInBits() >= totalDataCount * 8) {
          break;
        }
        buffer.put(PAD0, 8);
        if (buffer.getLengthInBits() >= totalDataCount * 8) {
          break;
        }
        buffer.put(PAD1, 8);
      }
      return createBytes(buffer, rsBlocks);
    };
    _this.addData = function(data, mode) {
      mode = mode || "Byte";
      let newData = null;
      switch (mode) {
        case "Numeric":
          newData = qrNumber(data);
          break;
        case "Alphanumeric":
          newData = qrAlphaNum(data);
          break;
        case "Byte":
          newData = qr8BitByte(data);
          break;
        case "Kanji":
          newData = qrKanji(data);
          break;
        default:
          throw "mode:" + mode;
      }
      _dataList.push(newData);
      _dataCache = null;
    };
    _this.isDark = function(row, col) {
      if (row < 0 || _moduleCount <= row || col < 0 || _moduleCount <= col) {
        throw row + "," + col;
      }
      return _modules[row][col];
    };
    _this.getModuleCount = function() {
      return _moduleCount;
    };
    _this.make = function() {
      if (_typeNumber < 1) {
        let typeNumber2 = 1;
        for (; typeNumber2 < 40; typeNumber2++) {
          const rsBlocks = QRRSBlock.getRSBlocks(typeNumber2, _errorCorrectionLevel);
          const buffer = qrBitBuffer();
          for (let i = 0; i < _dataList.length; i++) {
            const data = _dataList[i];
            buffer.put(data.getMode(), 4);
            buffer.put(data.getLength(), QRUtil.getLengthInBits(data.getMode(), typeNumber2));
            data.write(buffer);
          }
          let totalDataCount = 0;
          for (let i = 0; i < rsBlocks.length; i++) {
            totalDataCount += rsBlocks[i].dataCount;
          }
          if (buffer.getLengthInBits() <= totalDataCount * 8) {
            break;
          }
        }
        _typeNumber = typeNumber2;
      }
      makeImpl(false, getBestMaskPattern());
    };
    _this.createTableTag = function(cellSize, margin) {
      cellSize = cellSize || 2;
      margin = typeof margin == "undefined" ? cellSize * 4 : margin;
      let qrHtml = "";
      qrHtml += '<table style="';
      qrHtml += " border-width: 0px; border-style: none;";
      qrHtml += " border-collapse: collapse;";
      qrHtml += " padding: 0px; margin: " + margin + "px;";
      qrHtml += '">';
      qrHtml += "<tbody>";
      for (let r = 0; r < _this.getModuleCount(); r += 1) {
        qrHtml += "<tr>";
        for (let c = 0; c < _this.getModuleCount(); c += 1) {
          qrHtml += '<td style="';
          qrHtml += " border-width: 0px; border-style: none;";
          qrHtml += " border-collapse: collapse;";
          qrHtml += " padding: 0px; margin: 0px;";
          qrHtml += " width: " + cellSize + "px;";
          qrHtml += " height: " + cellSize + "px;";
          qrHtml += " background-color: ";
          qrHtml += _this.isDark(r, c) ? "#000000" : "#ffffff";
          qrHtml += ";";
          qrHtml += '"/>';
        }
        qrHtml += "</tr>";
      }
      qrHtml += "</tbody>";
      qrHtml += "</table>";
      return qrHtml;
    };
    _this.createSvgTag = function(cellSize, margin, alt, title) {
      let opts = {};
      if (typeof arguments[0] == "object") {
        opts = arguments[0];
        cellSize = opts.cellSize;
        margin = opts.margin;
        alt = opts.alt;
        title = opts.title;
      }
      cellSize = cellSize || 2;
      margin = typeof margin == "undefined" ? cellSize * 4 : margin;
      alt = typeof alt === "string" ? { text: alt } : alt || {};
      alt.text = alt.text || null;
      alt.id = alt.text ? alt.id || "qrcode-description" : null;
      title = typeof title === "string" ? { text: title } : title || {};
      title.text = title.text || null;
      title.id = title.text ? title.id || "qrcode-title" : null;
      const size = _this.getModuleCount() * cellSize + margin * 2;
      let c, mc, r, mr, qrSvg = "", rect;
      rect = "l" + cellSize + ",0 0," + cellSize + " -" + cellSize + ",0 0,-" + cellSize + "z ";
      qrSvg += '<svg version="1.1" xmlns="http://www.w3.org/2000/svg"';
      qrSvg += !opts.scalable ? ' width="' + size + 'px" height="' + size + 'px"' : "";
      qrSvg += ' viewBox="0 0 ' + size + " " + size + '" ';
      qrSvg += ' preserveAspectRatio="xMinYMin meet"';
      qrSvg += title.text || alt.text ? ' role="img" aria-labelledby="' + escapeXml([title.id, alt.id].join(" ").trim()) + '"' : "";
      qrSvg += ">";
      qrSvg += title.text ? '<title id="' + escapeXml(title.id) + '">' + escapeXml(title.text) + "</title>" : "";
      qrSvg += alt.text ? '<description id="' + escapeXml(alt.id) + '">' + escapeXml(alt.text) + "</description>" : "";
      qrSvg += '<rect width="100%" height="100%" fill="white" cx="0" cy="0"/>';
      qrSvg += '<path d="';
      for (r = 0; r < _this.getModuleCount(); r += 1) {
        mr = r * cellSize + margin;
        for (c = 0; c < _this.getModuleCount(); c += 1) {
          if (_this.isDark(r, c)) {
            mc = c * cellSize + margin;
            qrSvg += "M" + mc + "," + mr + rect;
          }
        }
      }
      qrSvg += '" stroke="transparent" fill="black"/>';
      qrSvg += "</svg>";
      return qrSvg;
    };
    _this.createDataURL = function(cellSize, margin) {
      cellSize = cellSize || 2;
      margin = typeof margin == "undefined" ? cellSize * 4 : margin;
      const size = _this.getModuleCount() * cellSize + margin * 2;
      const min = margin;
      const max = size - margin;
      return createDataURL(size, size, function(x, y) {
        if (min <= x && x < max && min <= y && y < max) {
          const c = Math.floor((x - min) / cellSize);
          const r = Math.floor((y - min) / cellSize);
          return _this.isDark(r, c) ? 0 : 1;
        } else {
          return 1;
        }
      });
    };
    _this.createImgTag = function(cellSize, margin, alt) {
      cellSize = cellSize || 2;
      margin = typeof margin == "undefined" ? cellSize * 4 : margin;
      const size = _this.getModuleCount() * cellSize + margin * 2;
      let img = "";
      img += "<img";
      img += ' src="';
      img += _this.createDataURL(cellSize, margin);
      img += '"';
      img += ' width="';
      img += size;
      img += '"';
      img += ' height="';
      img += size;
      img += '"';
      if (alt) {
        img += ' alt="';
        img += escapeXml(alt);
        img += '"';
      }
      img += "/>";
      return img;
    };
    const escapeXml = function(s) {
      let escaped = "";
      for (let i = 0; i < s.length; i += 1) {
        const c = s.charAt(i);
        switch (c) {
          case "<":
            escaped += "&lt;";
            break;
          case ">":
            escaped += "&gt;";
            break;
          case "&":
            escaped += "&amp;";
            break;
          case '"':
            escaped += "&quot;";
            break;
          default:
            escaped += c;
            break;
        }
      }
      return escaped;
    };
    const _createHalfASCII = function(margin) {
      const cellSize = 1;
      margin = typeof margin == "undefined" ? cellSize * 2 : margin;
      const size = _this.getModuleCount() * cellSize + margin * 2;
      const min = margin;
      const max = size - margin;
      let y, x, r1, r2, p;
      const blocks = {
        "\u2588\u2588": "\u2588",
        "\u2588 ": "\u2580",
        " \u2588": "\u2584",
        "  ": " "
      };
      const blocksLastLineNoMargin = {
        "\u2588\u2588": "\u2580",
        "\u2588 ": "\u2580",
        " \u2588": " ",
        "  ": " "
      };
      let ascii = "";
      for (y = 0; y < size; y += 2) {
        r1 = Math.floor((y - min) / cellSize);
        r2 = Math.floor((y + 1 - min) / cellSize);
        for (x = 0; x < size; x += 1) {
          p = "\u2588";
          if (min <= x && x < max && min <= y && y < max && _this.isDark(r1, Math.floor((x - min) / cellSize))) {
            p = " ";
          }
          if (min <= x && x < max && min <= y + 1 && y + 1 < max && _this.isDark(r2, Math.floor((x - min) / cellSize))) {
            p += " ";
          } else {
            p += "\u2588";
          }
          ascii += margin < 1 && y + 1 >= max ? blocksLastLineNoMargin[p] : blocks[p];
        }
        ascii += "\n";
      }
      if (size % 2 && margin > 0) {
        return ascii.substring(0, ascii.length - size - 1) + Array(size + 1).join("\u2580");
      }
      return ascii.substring(0, ascii.length - 1);
    };
    _this.createASCII = function(cellSize, margin) {
      cellSize = cellSize || 1;
      if (cellSize < 2) {
        return _createHalfASCII(margin);
      }
      cellSize -= 1;
      margin = typeof margin == "undefined" ? cellSize * 2 : margin;
      const size = _this.getModuleCount() * cellSize + margin * 2;
      const min = margin;
      const max = size - margin;
      let y, x, r, p;
      const white = Array(cellSize + 1).join("\u2588\u2588");
      const black = Array(cellSize + 1).join("  ");
      let ascii = "";
      let line = "";
      for (y = 0; y < size; y += 1) {
        r = Math.floor((y - min) / cellSize);
        line = "";
        for (x = 0; x < size; x += 1) {
          p = 1;
          if (min <= x && x < max && min <= y && y < max && _this.isDark(r, Math.floor((x - min) / cellSize))) {
            p = 0;
          }
          line += p ? white : black;
        }
        for (r = 0; r < cellSize; r += 1) {
          ascii += line + "\n";
        }
      }
      return ascii.substring(0, ascii.length - 1);
    };
    _this.renderTo2dContext = function(context, cellSize) {
      cellSize = cellSize || 2;
      const length = _this.getModuleCount();
      for (let row = 0; row < length; row++) {
        for (let col = 0; col < length; col++) {
          context.fillStyle = _this.isDark(row, col) ? "black" : "white";
          context.fillRect(col * cellSize, row * cellSize, cellSize, cellSize);
        }
      }
    };
    return _this;
  };
  qrcode.stringToBytes = function(s) {
    const bytes = [];
    for (let i = 0; i < s.length; i += 1) {
      const c = s.charCodeAt(i);
      bytes.push(c & 255);
    }
    return bytes;
  };
  qrcode.createStringToBytes = function(unicodeData, numChars) {
    const unicodeMap = (function() {
      const bin = base64DecodeInputStream(unicodeData);
      const read = function() {
        const b = bin.read();
        if (b == -1) throw "eof";
        return b;
      };
      let count = 0;
      const unicodeMap2 = {};
      while (true) {
        const b0 = bin.read();
        if (b0 == -1) break;
        const b1 = read();
        const b2 = read();
        const b3 = read();
        const k = String.fromCharCode(b0 << 8 | b1);
        const v = b2 << 8 | b3;
        unicodeMap2[k] = v;
        count += 1;
      }
      if (count != numChars) {
        throw count + " != " + numChars;
      }
      return unicodeMap2;
    })();
    const unknownChar = "?".charCodeAt(0);
    return function(s) {
      const bytes = [];
      for (let i = 0; i < s.length; i += 1) {
        const c = s.charCodeAt(i);
        if (c < 128) {
          bytes.push(c);
        } else {
          const b = unicodeMap[s.charAt(i)];
          if (typeof b == "number") {
            if ((b & 255) == b) {
              bytes.push(b);
            } else {
              bytes.push(b >>> 8);
              bytes.push(b & 255);
            }
          } else {
            bytes.push(unknownChar);
          }
        }
      }
      return bytes;
    };
  };
  var QRMode = {
    MODE_NUMBER: 1 << 0,
    MODE_ALPHA_NUM: 1 << 1,
    MODE_8BIT_BYTE: 1 << 2,
    MODE_KANJI: 1 << 3
  };
  var QRErrorCorrectionLevel = {
    L: 1,
    M: 0,
    Q: 3,
    H: 2
  };
  var QRMaskPattern = {
    PATTERN000: 0,
    PATTERN001: 1,
    PATTERN010: 2,
    PATTERN011: 3,
    PATTERN100: 4,
    PATTERN101: 5,
    PATTERN110: 6,
    PATTERN111: 7
  };
  var QRUtil = (function() {
    const PATTERN_POSITION_TABLE = [
      [],
      [6, 18],
      [6, 22],
      [6, 26],
      [6, 30],
      [6, 34],
      [6, 22, 38],
      [6, 24, 42],
      [6, 26, 46],
      [6, 28, 50],
      [6, 30, 54],
      [6, 32, 58],
      [6, 34, 62],
      [6, 26, 46, 66],
      [6, 26, 48, 70],
      [6, 26, 50, 74],
      [6, 30, 54, 78],
      [6, 30, 56, 82],
      [6, 30, 58, 86],
      [6, 34, 62, 90],
      [6, 28, 50, 72, 94],
      [6, 26, 50, 74, 98],
      [6, 30, 54, 78, 102],
      [6, 28, 54, 80, 106],
      [6, 32, 58, 84, 110],
      [6, 30, 58, 86, 114],
      [6, 34, 62, 90, 118],
      [6, 26, 50, 74, 98, 122],
      [6, 30, 54, 78, 102, 126],
      [6, 26, 52, 78, 104, 130],
      [6, 30, 56, 82, 108, 134],
      [6, 34, 60, 86, 112, 138],
      [6, 30, 58, 86, 114, 142],
      [6, 34, 62, 90, 118, 146],
      [6, 30, 54, 78, 102, 126, 150],
      [6, 24, 50, 76, 102, 128, 154],
      [6, 28, 54, 80, 106, 132, 158],
      [6, 32, 58, 84, 110, 136, 162],
      [6, 26, 54, 82, 110, 138, 166],
      [6, 30, 58, 86, 114, 142, 170]
    ];
    const G15 = 1 << 10 | 1 << 8 | 1 << 5 | 1 << 4 | 1 << 2 | 1 << 1 | 1 << 0;
    const G18 = 1 << 12 | 1 << 11 | 1 << 10 | 1 << 9 | 1 << 8 | 1 << 5 | 1 << 2 | 1 << 0;
    const G15_MASK = 1 << 14 | 1 << 12 | 1 << 10 | 1 << 4 | 1 << 1;
    const _this = {};
    const getBCHDigit = function(data) {
      let digit = 0;
      while (data != 0) {
        digit += 1;
        data >>>= 1;
      }
      return digit;
    };
    _this.getBCHTypeInfo = function(data) {
      let d = data << 10;
      while (getBCHDigit(d) - getBCHDigit(G15) >= 0) {
        d ^= G15 << getBCHDigit(d) - getBCHDigit(G15);
      }
      return (data << 10 | d) ^ G15_MASK;
    };
    _this.getBCHTypeNumber = function(data) {
      let d = data << 12;
      while (getBCHDigit(d) - getBCHDigit(G18) >= 0) {
        d ^= G18 << getBCHDigit(d) - getBCHDigit(G18);
      }
      return data << 12 | d;
    };
    _this.getPatternPosition = function(typeNumber) {
      return PATTERN_POSITION_TABLE[typeNumber - 1];
    };
    _this.getMaskFunction = function(maskPattern) {
      switch (maskPattern) {
        case QRMaskPattern.PATTERN000:
          return function(i, j) {
            return (i + j) % 2 == 0;
          };
        case QRMaskPattern.PATTERN001:
          return function(i, j) {
            return i % 2 == 0;
          };
        case QRMaskPattern.PATTERN010:
          return function(i, j) {
            return j % 3 == 0;
          };
        case QRMaskPattern.PATTERN011:
          return function(i, j) {
            return (i + j) % 3 == 0;
          };
        case QRMaskPattern.PATTERN100:
          return function(i, j) {
            return (Math.floor(i / 2) + Math.floor(j / 3)) % 2 == 0;
          };
        case QRMaskPattern.PATTERN101:
          return function(i, j) {
            return i * j % 2 + i * j % 3 == 0;
          };
        case QRMaskPattern.PATTERN110:
          return function(i, j) {
            return (i * j % 2 + i * j % 3) % 2 == 0;
          };
        case QRMaskPattern.PATTERN111:
          return function(i, j) {
            return (i * j % 3 + (i + j) % 2) % 2 == 0;
          };
        default:
          throw "bad maskPattern:" + maskPattern;
      }
    };
    _this.getErrorCorrectPolynomial = function(errorCorrectLength) {
      let a = qrPolynomial([1], 0);
      for (let i = 0; i < errorCorrectLength; i += 1) {
        a = a.multiply(qrPolynomial([1, QRMath.gexp(i)], 0));
      }
      return a;
    };
    _this.getLengthInBits = function(mode, type) {
      if (1 <= type && type < 10) {
        switch (mode) {
          case QRMode.MODE_NUMBER:
            return 10;
          case QRMode.MODE_ALPHA_NUM:
            return 9;
          case QRMode.MODE_8BIT_BYTE:
            return 8;
          case QRMode.MODE_KANJI:
            return 8;
          default:
            throw "mode:" + mode;
        }
      } else if (type < 27) {
        switch (mode) {
          case QRMode.MODE_NUMBER:
            return 12;
          case QRMode.MODE_ALPHA_NUM:
            return 11;
          case QRMode.MODE_8BIT_BYTE:
            return 16;
          case QRMode.MODE_KANJI:
            return 10;
          default:
            throw "mode:" + mode;
        }
      } else if (type < 41) {
        switch (mode) {
          case QRMode.MODE_NUMBER:
            return 14;
          case QRMode.MODE_ALPHA_NUM:
            return 13;
          case QRMode.MODE_8BIT_BYTE:
            return 16;
          case QRMode.MODE_KANJI:
            return 12;
          default:
            throw "mode:" + mode;
        }
      } else {
        throw "type:" + type;
      }
    };
    _this.getLostPoint = function(qrcode2) {
      const moduleCount = qrcode2.getModuleCount();
      let lostPoint = 0;
      for (let row = 0; row < moduleCount; row += 1) {
        for (let col = 0; col < moduleCount; col += 1) {
          let sameCount = 0;
          const dark = qrcode2.isDark(row, col);
          for (let r = -1; r <= 1; r += 1) {
            if (row + r < 0 || moduleCount <= row + r) {
              continue;
            }
            for (let c = -1; c <= 1; c += 1) {
              if (col + c < 0 || moduleCount <= col + c) {
                continue;
              }
              if (r == 0 && c == 0) {
                continue;
              }
              if (dark == qrcode2.isDark(row + r, col + c)) {
                sameCount += 1;
              }
            }
          }
          if (sameCount > 5) {
            lostPoint += 3 + sameCount - 5;
          }
        }
      }
      ;
      for (let row = 0; row < moduleCount - 1; row += 1) {
        for (let col = 0; col < moduleCount - 1; col += 1) {
          let count = 0;
          if (qrcode2.isDark(row, col)) count += 1;
          if (qrcode2.isDark(row + 1, col)) count += 1;
          if (qrcode2.isDark(row, col + 1)) count += 1;
          if (qrcode2.isDark(row + 1, col + 1)) count += 1;
          if (count == 0 || count == 4) {
            lostPoint += 3;
          }
        }
      }
      for (let row = 0; row < moduleCount; row += 1) {
        for (let col = 0; col < moduleCount - 6; col += 1) {
          if (qrcode2.isDark(row, col) && !qrcode2.isDark(row, col + 1) && qrcode2.isDark(row, col + 2) && qrcode2.isDark(row, col + 3) && qrcode2.isDark(row, col + 4) && !qrcode2.isDark(row, col + 5) && qrcode2.isDark(row, col + 6)) {
            lostPoint += 40;
          }
        }
      }
      for (let col = 0; col < moduleCount; col += 1) {
        for (let row = 0; row < moduleCount - 6; row += 1) {
          if (qrcode2.isDark(row, col) && !qrcode2.isDark(row + 1, col) && qrcode2.isDark(row + 2, col) && qrcode2.isDark(row + 3, col) && qrcode2.isDark(row + 4, col) && !qrcode2.isDark(row + 5, col) && qrcode2.isDark(row + 6, col)) {
            lostPoint += 40;
          }
        }
      }
      let darkCount = 0;
      for (let col = 0; col < moduleCount; col += 1) {
        for (let row = 0; row < moduleCount; row += 1) {
          if (qrcode2.isDark(row, col)) {
            darkCount += 1;
          }
        }
      }
      const ratio = Math.abs(100 * darkCount / moduleCount / moduleCount - 50) / 5;
      lostPoint += ratio * 10;
      return lostPoint;
    };
    return _this;
  })();
  var QRMath = (function() {
    const EXP_TABLE = new Array(256);
    const LOG_TABLE = new Array(256);
    for (let i = 0; i < 8; i += 1) {
      EXP_TABLE[i] = 1 << i;
    }
    for (let i = 8; i < 256; i += 1) {
      EXP_TABLE[i] = EXP_TABLE[i - 4] ^ EXP_TABLE[i - 5] ^ EXP_TABLE[i - 6] ^ EXP_TABLE[i - 8];
    }
    for (let i = 0; i < 255; i += 1) {
      LOG_TABLE[EXP_TABLE[i]] = i;
    }
    const _this = {};
    _this.glog = function(n) {
      if (n < 1) {
        throw "glog(" + n + ")";
      }
      return LOG_TABLE[n];
    };
    _this.gexp = function(n) {
      while (n < 0) {
        n += 255;
      }
      while (n >= 256) {
        n -= 255;
      }
      return EXP_TABLE[n];
    };
    return _this;
  })();
  var qrPolynomial = function(num, shift) {
    if (typeof num.length == "undefined") {
      throw num.length + "/" + shift;
    }
    const _num = (function() {
      let offset = 0;
      while (offset < num.length && num[offset] == 0) {
        offset += 1;
      }
      const _num2 = new Array(num.length - offset + shift);
      for (let i = 0; i < num.length - offset; i += 1) {
        _num2[i] = num[i + offset];
      }
      return _num2;
    })();
    const _this = {};
    _this.getAt = function(index) {
      return _num[index];
    };
    _this.getLength = function() {
      return _num.length;
    };
    _this.multiply = function(e) {
      const num2 = new Array(_this.getLength() + e.getLength() - 1);
      for (let i = 0; i < _this.getLength(); i += 1) {
        for (let j = 0; j < e.getLength(); j += 1) {
          num2[i + j] ^= QRMath.gexp(QRMath.glog(_this.getAt(i)) + QRMath.glog(e.getAt(j)));
        }
      }
      return qrPolynomial(num2, 0);
    };
    _this.mod = function(e) {
      if (_this.getLength() - e.getLength() < 0) {
        return _this;
      }
      const ratio = QRMath.glog(_this.getAt(0)) - QRMath.glog(e.getAt(0));
      const num2 = new Array(_this.getLength());
      for (let i = 0; i < _this.getLength(); i += 1) {
        num2[i] = _this.getAt(i);
      }
      for (let i = 0; i < e.getLength(); i += 1) {
        num2[i] ^= QRMath.gexp(QRMath.glog(e.getAt(i)) + ratio);
      }
      return qrPolynomial(num2, 0).mod(e);
    };
    return _this;
  };
  var QRRSBlock = (function() {
    const RS_BLOCK_TABLE = [
      // L
      // M
      // Q
      // H
      // 1
      [1, 26, 19],
      [1, 26, 16],
      [1, 26, 13],
      [1, 26, 9],
      // 2
      [1, 44, 34],
      [1, 44, 28],
      [1, 44, 22],
      [1, 44, 16],
      // 3
      [1, 70, 55],
      [1, 70, 44],
      [2, 35, 17],
      [2, 35, 13],
      // 4
      [1, 100, 80],
      [2, 50, 32],
      [2, 50, 24],
      [4, 25, 9],
      // 5
      [1, 134, 108],
      [2, 67, 43],
      [2, 33, 15, 2, 34, 16],
      [2, 33, 11, 2, 34, 12],
      // 6
      [2, 86, 68],
      [4, 43, 27],
      [4, 43, 19],
      [4, 43, 15],
      // 7
      [2, 98, 78],
      [4, 49, 31],
      [2, 32, 14, 4, 33, 15],
      [4, 39, 13, 1, 40, 14],
      // 8
      [2, 121, 97],
      [2, 60, 38, 2, 61, 39],
      [4, 40, 18, 2, 41, 19],
      [4, 40, 14, 2, 41, 15],
      // 9
      [2, 146, 116],
      [3, 58, 36, 2, 59, 37],
      [4, 36, 16, 4, 37, 17],
      [4, 36, 12, 4, 37, 13],
      // 10
      [2, 86, 68, 2, 87, 69],
      [4, 69, 43, 1, 70, 44],
      [6, 43, 19, 2, 44, 20],
      [6, 43, 15, 2, 44, 16],
      // 11
      [4, 101, 81],
      [1, 80, 50, 4, 81, 51],
      [4, 50, 22, 4, 51, 23],
      [3, 36, 12, 8, 37, 13],
      // 12
      [2, 116, 92, 2, 117, 93],
      [6, 58, 36, 2, 59, 37],
      [4, 46, 20, 6, 47, 21],
      [7, 42, 14, 4, 43, 15],
      // 13
      [4, 133, 107],
      [8, 59, 37, 1, 60, 38],
      [8, 44, 20, 4, 45, 21],
      [12, 33, 11, 4, 34, 12],
      // 14
      [3, 145, 115, 1, 146, 116],
      [4, 64, 40, 5, 65, 41],
      [11, 36, 16, 5, 37, 17],
      [11, 36, 12, 5, 37, 13],
      // 15
      [5, 109, 87, 1, 110, 88],
      [5, 65, 41, 5, 66, 42],
      [5, 54, 24, 7, 55, 25],
      [11, 36, 12, 7, 37, 13],
      // 16
      [5, 122, 98, 1, 123, 99],
      [7, 73, 45, 3, 74, 46],
      [15, 43, 19, 2, 44, 20],
      [3, 45, 15, 13, 46, 16],
      // 17
      [1, 135, 107, 5, 136, 108],
      [10, 74, 46, 1, 75, 47],
      [1, 50, 22, 15, 51, 23],
      [2, 42, 14, 17, 43, 15],
      // 18
      [5, 150, 120, 1, 151, 121],
      [9, 69, 43, 4, 70, 44],
      [17, 50, 22, 1, 51, 23],
      [2, 42, 14, 19, 43, 15],
      // 19
      [3, 141, 113, 4, 142, 114],
      [3, 70, 44, 11, 71, 45],
      [17, 47, 21, 4, 48, 22],
      [9, 39, 13, 16, 40, 14],
      // 20
      [3, 135, 107, 5, 136, 108],
      [3, 67, 41, 13, 68, 42],
      [15, 54, 24, 5, 55, 25],
      [15, 43, 15, 10, 44, 16],
      // 21
      [4, 144, 116, 4, 145, 117],
      [17, 68, 42],
      [17, 50, 22, 6, 51, 23],
      [19, 46, 16, 6, 47, 17],
      // 22
      [2, 139, 111, 7, 140, 112],
      [17, 74, 46],
      [7, 54, 24, 16, 55, 25],
      [34, 37, 13],
      // 23
      [4, 151, 121, 5, 152, 122],
      [4, 75, 47, 14, 76, 48],
      [11, 54, 24, 14, 55, 25],
      [16, 45, 15, 14, 46, 16],
      // 24
      [6, 147, 117, 4, 148, 118],
      [6, 73, 45, 14, 74, 46],
      [11, 54, 24, 16, 55, 25],
      [30, 46, 16, 2, 47, 17],
      // 25
      [8, 132, 106, 4, 133, 107],
      [8, 75, 47, 13, 76, 48],
      [7, 54, 24, 22, 55, 25],
      [22, 45, 15, 13, 46, 16],
      // 26
      [10, 142, 114, 2, 143, 115],
      [19, 74, 46, 4, 75, 47],
      [28, 50, 22, 6, 51, 23],
      [33, 46, 16, 4, 47, 17],
      // 27
      [8, 152, 122, 4, 153, 123],
      [22, 73, 45, 3, 74, 46],
      [8, 53, 23, 26, 54, 24],
      [12, 45, 15, 28, 46, 16],
      // 28
      [3, 147, 117, 10, 148, 118],
      [3, 73, 45, 23, 74, 46],
      [4, 54, 24, 31, 55, 25],
      [11, 45, 15, 31, 46, 16],
      // 29
      [7, 146, 116, 7, 147, 117],
      [21, 73, 45, 7, 74, 46],
      [1, 53, 23, 37, 54, 24],
      [19, 45, 15, 26, 46, 16],
      // 30
      [5, 145, 115, 10, 146, 116],
      [19, 75, 47, 10, 76, 48],
      [15, 54, 24, 25, 55, 25],
      [23, 45, 15, 25, 46, 16],
      // 31
      [13, 145, 115, 3, 146, 116],
      [2, 74, 46, 29, 75, 47],
      [42, 54, 24, 1, 55, 25],
      [23, 45, 15, 28, 46, 16],
      // 32
      [17, 145, 115],
      [10, 74, 46, 23, 75, 47],
      [10, 54, 24, 35, 55, 25],
      [19, 45, 15, 35, 46, 16],
      // 33
      [17, 145, 115, 1, 146, 116],
      [14, 74, 46, 21, 75, 47],
      [29, 54, 24, 19, 55, 25],
      [11, 45, 15, 46, 46, 16],
      // 34
      [13, 145, 115, 6, 146, 116],
      [14, 74, 46, 23, 75, 47],
      [44, 54, 24, 7, 55, 25],
      [59, 46, 16, 1, 47, 17],
      // 35
      [12, 151, 121, 7, 152, 122],
      [12, 75, 47, 26, 76, 48],
      [39, 54, 24, 14, 55, 25],
      [22, 45, 15, 41, 46, 16],
      // 36
      [6, 151, 121, 14, 152, 122],
      [6, 75, 47, 34, 76, 48],
      [46, 54, 24, 10, 55, 25],
      [2, 45, 15, 64, 46, 16],
      // 37
      [17, 152, 122, 4, 153, 123],
      [29, 74, 46, 14, 75, 47],
      [49, 54, 24, 10, 55, 25],
      [24, 45, 15, 46, 46, 16],
      // 38
      [4, 152, 122, 18, 153, 123],
      [13, 74, 46, 32, 75, 47],
      [48, 54, 24, 14, 55, 25],
      [42, 45, 15, 32, 46, 16],
      // 39
      [20, 147, 117, 4, 148, 118],
      [40, 75, 47, 7, 76, 48],
      [43, 54, 24, 22, 55, 25],
      [10, 45, 15, 67, 46, 16],
      // 40
      [19, 148, 118, 6, 149, 119],
      [18, 75, 47, 31, 76, 48],
      [34, 54, 24, 34, 55, 25],
      [20, 45, 15, 61, 46, 16]
    ];
    const qrRSBlock = function(totalCount, dataCount) {
      const _this2 = {};
      _this2.totalCount = totalCount;
      _this2.dataCount = dataCount;
      return _this2;
    };
    const _this = {};
    const getRsBlockTable = function(typeNumber, errorCorrectionLevel) {
      switch (errorCorrectionLevel) {
        case QRErrorCorrectionLevel.L:
          return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 0];
        case QRErrorCorrectionLevel.M:
          return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 1];
        case QRErrorCorrectionLevel.Q:
          return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 2];
        case QRErrorCorrectionLevel.H:
          return RS_BLOCK_TABLE[(typeNumber - 1) * 4 + 3];
        default:
          return void 0;
      }
    };
    _this.getRSBlocks = function(typeNumber, errorCorrectionLevel) {
      const rsBlock = getRsBlockTable(typeNumber, errorCorrectionLevel);
      if (typeof rsBlock == "undefined") {
        throw "bad rs block @ typeNumber:" + typeNumber + "/errorCorrectionLevel:" + errorCorrectionLevel;
      }
      const length = rsBlock.length / 3;
      const list = [];
      for (let i = 0; i < length; i += 1) {
        const count = rsBlock[i * 3 + 0];
        const totalCount = rsBlock[i * 3 + 1];
        const dataCount = rsBlock[i * 3 + 2];
        for (let j = 0; j < count; j += 1) {
          list.push(qrRSBlock(totalCount, dataCount));
        }
      }
      return list;
    };
    return _this;
  })();
  var qrBitBuffer = function() {
    const _buffer = [];
    let _length = 0;
    const _this = {};
    _this.getBuffer = function() {
      return _buffer;
    };
    _this.getAt = function(index) {
      const bufIndex = Math.floor(index / 8);
      return (_buffer[bufIndex] >>> 7 - index % 8 & 1) == 1;
    };
    _this.put = function(num, length) {
      for (let i = 0; i < length; i += 1) {
        _this.putBit((num >>> length - i - 1 & 1) == 1);
      }
    };
    _this.getLengthInBits = function() {
      return _length;
    };
    _this.putBit = function(bit) {
      const bufIndex = Math.floor(_length / 8);
      if (_buffer.length <= bufIndex) {
        _buffer.push(0);
      }
      if (bit) {
        _buffer[bufIndex] |= 128 >>> _length % 8;
      }
      _length += 1;
    };
    return _this;
  };
  var qrNumber = function(data) {
    const _mode = QRMode.MODE_NUMBER;
    const _data = data;
    const _this = {};
    _this.getMode = function() {
      return _mode;
    };
    _this.getLength = function(buffer) {
      return _data.length;
    };
    _this.write = function(buffer) {
      const data2 = _data;
      let i = 0;
      while (i + 2 < data2.length) {
        buffer.put(strToNum(data2.substring(i, i + 3)), 10);
        i += 3;
      }
      if (i < data2.length) {
        if (data2.length - i == 1) {
          buffer.put(strToNum(data2.substring(i, i + 1)), 4);
        } else if (data2.length - i == 2) {
          buffer.put(strToNum(data2.substring(i, i + 2)), 7);
        }
      }
    };
    const strToNum = function(s) {
      let num = 0;
      for (let i = 0; i < s.length; i += 1) {
        num = num * 10 + chatToNum(s.charAt(i));
      }
      return num;
    };
    const chatToNum = function(c) {
      if ("0" <= c && c <= "9") {
        return c.charCodeAt(0) - "0".charCodeAt(0);
      }
      throw "illegal char :" + c;
    };
    return _this;
  };
  var qrAlphaNum = function(data) {
    const _mode = QRMode.MODE_ALPHA_NUM;
    const _data = data;
    const _this = {};
    _this.getMode = function() {
      return _mode;
    };
    _this.getLength = function(buffer) {
      return _data.length;
    };
    _this.write = function(buffer) {
      const s = _data;
      let i = 0;
      while (i + 1 < s.length) {
        buffer.put(
          getCode(s.charAt(i)) * 45 + getCode(s.charAt(i + 1)),
          11
        );
        i += 2;
      }
      if (i < s.length) {
        buffer.put(getCode(s.charAt(i)), 6);
      }
    };
    const getCode = function(c) {
      if ("0" <= c && c <= "9") {
        return c.charCodeAt(0) - "0".charCodeAt(0);
      } else if ("A" <= c && c <= "Z") {
        return c.charCodeAt(0) - "A".charCodeAt(0) + 10;
      } else {
        switch (c) {
          case " ":
            return 36;
          case "$":
            return 37;
          case "%":
            return 38;
          case "*":
            return 39;
          case "+":
            return 40;
          case "-":
            return 41;
          case ".":
            return 42;
          case "/":
            return 43;
          case ":":
            return 44;
          default:
            throw "illegal char :" + c;
        }
      }
    };
    return _this;
  };
  var qr8BitByte = function(data) {
    const _mode = QRMode.MODE_8BIT_BYTE;
    const _data = data;
    const _bytes = qrcode.stringToBytes(data);
    const _this = {};
    _this.getMode = function() {
      return _mode;
    };
    _this.getLength = function(buffer) {
      return _bytes.length;
    };
    _this.write = function(buffer) {
      for (let i = 0; i < _bytes.length; i += 1) {
        buffer.put(_bytes[i], 8);
      }
    };
    return _this;
  };
  var qrKanji = function(data) {
    const _mode = QRMode.MODE_KANJI;
    const _data = data;
    const stringToBytes2 = qrcode.stringToBytes;
    !(function(c, code) {
      const test = stringToBytes2(c);
      if (test.length != 2 || (test[0] << 8 | test[1]) != code) {
        throw "sjis not supported.";
      }
    })("\u53CB", 38726);
    const _bytes = stringToBytes2(data);
    const _this = {};
    _this.getMode = function() {
      return _mode;
    };
    _this.getLength = function(buffer) {
      return ~~(_bytes.length / 2);
    };
    _this.write = function(buffer) {
      const data2 = _bytes;
      let i = 0;
      while (i + 1 < data2.length) {
        let c = (255 & data2[i]) << 8 | 255 & data2[i + 1];
        if (33088 <= c && c <= 40956) {
          c -= 33088;
        } else if (57408 <= c && c <= 60351) {
          c -= 49472;
        } else {
          throw "illegal char at " + (i + 1) + "/" + c;
        }
        c = (c >>> 8 & 255) * 192 + (c & 255);
        buffer.put(c, 13);
        i += 2;
      }
      if (i < data2.length) {
        throw "illegal char at " + (i + 1);
      }
    };
    return _this;
  };
  var byteArrayOutputStream = function() {
    const _bytes = [];
    const _this = {};
    _this.writeByte = function(b) {
      _bytes.push(b & 255);
    };
    _this.writeShort = function(i) {
      _this.writeByte(i);
      _this.writeByte(i >>> 8);
    };
    _this.writeBytes = function(b, off, len) {
      off = off || 0;
      len = len || b.length;
      for (let i = 0; i < len; i += 1) {
        _this.writeByte(b[i + off]);
      }
    };
    _this.writeString = function(s) {
      for (let i = 0; i < s.length; i += 1) {
        _this.writeByte(s.charCodeAt(i));
      }
    };
    _this.toByteArray = function() {
      return _bytes;
    };
    _this.toString = function() {
      let s = "";
      s += "[";
      for (let i = 0; i < _bytes.length; i += 1) {
        if (i > 0) {
          s += ",";
        }
        s += _bytes[i];
      }
      s += "]";
      return s;
    };
    return _this;
  };
  var base64EncodeOutputStream = function() {
    let _buffer = 0;
    let _buflen = 0;
    let _length = 0;
    let _base64 = "";
    const _this = {};
    const writeEncoded = function(b) {
      _base64 += String.fromCharCode(encode(b & 63));
    };
    const encode = function(n) {
      if (n < 0) {
        throw "n:" + n;
      } else if (n < 26) {
        return 65 + n;
      } else if (n < 52) {
        return 97 + (n - 26);
      } else if (n < 62) {
        return 48 + (n - 52);
      } else if (n == 62) {
        return 43;
      } else if (n == 63) {
        return 47;
      } else {
        throw "n:" + n;
      }
    };
    _this.writeByte = function(n) {
      _buffer = _buffer << 8 | n & 255;
      _buflen += 8;
      _length += 1;
      while (_buflen >= 6) {
        writeEncoded(_buffer >>> _buflen - 6);
        _buflen -= 6;
      }
    };
    _this.flush = function() {
      if (_buflen > 0) {
        writeEncoded(_buffer << 6 - _buflen);
        _buffer = 0;
        _buflen = 0;
      }
      if (_length % 3 != 0) {
        const padlen = 3 - _length % 3;
        for (let i = 0; i < padlen; i += 1) {
          _base64 += "=";
        }
      }
    };
    _this.toString = function() {
      return _base64;
    };
    return _this;
  };
  var base64DecodeInputStream = function(str) {
    const _str = str;
    let _pos = 0;
    let _buffer = 0;
    let _buflen = 0;
    const _this = {};
    _this.read = function() {
      while (_buflen < 8) {
        if (_pos >= _str.length) {
          if (_buflen == 0) {
            return -1;
          }
          throw "unexpected end of file./" + _buflen;
        }
        const c = _str.charAt(_pos);
        _pos += 1;
        if (c == "=") {
          _buflen = 0;
          return -1;
        } else if (c.match(/^\s$/)) {
          continue;
        }
        _buffer = _buffer << 6 | decode(c.charCodeAt(0));
        _buflen += 6;
      }
      const n = _buffer >>> _buflen - 8 & 255;
      _buflen -= 8;
      return n;
    };
    const decode = function(c) {
      if (65 <= c && c <= 90) {
        return c - 65;
      } else if (97 <= c && c <= 122) {
        return c - 97 + 26;
      } else if (48 <= c && c <= 57) {
        return c - 48 + 52;
      } else if (c == 43) {
        return 62;
      } else if (c == 47) {
        return 63;
      } else {
        throw "c:" + c;
      }
    };
    return _this;
  };
  var gifImage = function(width, height) {
    const _width = width;
    const _height = height;
    const _data = new Array(width * height);
    const _this = {};
    _this.setPixel = function(x, y, pixel) {
      _data[y * _width + x] = pixel;
    };
    _this.write = function(out) {
      out.writeString("GIF87a");
      out.writeShort(_width);
      out.writeShort(_height);
      out.writeByte(128);
      out.writeByte(0);
      out.writeByte(0);
      out.writeByte(0);
      out.writeByte(0);
      out.writeByte(0);
      out.writeByte(255);
      out.writeByte(255);
      out.writeByte(255);
      out.writeString(",");
      out.writeShort(0);
      out.writeShort(0);
      out.writeShort(_width);
      out.writeShort(_height);
      out.writeByte(0);
      const lzwMinCodeSize = 2;
      const raster = getLZWRaster(lzwMinCodeSize);
      out.writeByte(lzwMinCodeSize);
      let offset = 0;
      while (raster.length - offset > 255) {
        out.writeByte(255);
        out.writeBytes(raster, offset, 255);
        offset += 255;
      }
      out.writeByte(raster.length - offset);
      out.writeBytes(raster, offset, raster.length - offset);
      out.writeByte(0);
      out.writeString(";");
    };
    const bitOutputStream = function(out) {
      const _out = out;
      let _bitLength = 0;
      let _bitBuffer = 0;
      const _this2 = {};
      _this2.write = function(data, length) {
        if (data >>> length != 0) {
          throw "length over";
        }
        while (_bitLength + length >= 8) {
          _out.writeByte(255 & (data << _bitLength | _bitBuffer));
          length -= 8 - _bitLength;
          data >>>= 8 - _bitLength;
          _bitBuffer = 0;
          _bitLength = 0;
        }
        _bitBuffer = data << _bitLength | _bitBuffer;
        _bitLength = _bitLength + length;
      };
      _this2.flush = function() {
        if (_bitLength > 0) {
          _out.writeByte(_bitBuffer);
        }
      };
      return _this2;
    };
    const getLZWRaster = function(lzwMinCodeSize) {
      const clearCode = 1 << lzwMinCodeSize;
      const endCode = (1 << lzwMinCodeSize) + 1;
      let bitLength = lzwMinCodeSize + 1;
      const table = lzwTable();
      for (let i = 0; i < clearCode; i += 1) {
        table.add(String.fromCharCode(i));
      }
      table.add(String.fromCharCode(clearCode));
      table.add(String.fromCharCode(endCode));
      const byteOut = byteArrayOutputStream();
      const bitOut = bitOutputStream(byteOut);
      bitOut.write(clearCode, bitLength);
      let dataIndex = 0;
      let s = String.fromCharCode(_data[dataIndex]);
      dataIndex += 1;
      while (dataIndex < _data.length) {
        const c = String.fromCharCode(_data[dataIndex]);
        dataIndex += 1;
        if (table.contains(s + c)) {
          s = s + c;
        } else {
          bitOut.write(table.indexOf(s), bitLength);
          if (table.size() < 4095) {
            if (table.size() == 1 << bitLength) {
              bitLength += 1;
            }
            table.add(s + c);
          }
          s = c;
        }
      }
      bitOut.write(table.indexOf(s), bitLength);
      bitOut.write(endCode, bitLength);
      bitOut.flush();
      return byteOut.toByteArray();
    };
    const lzwTable = function() {
      const _map = {};
      let _size = 0;
      const _this2 = {};
      _this2.add = function(key) {
        if (_this2.contains(key)) {
          throw "dup key:" + key;
        }
        _map[key] = _size;
        _size += 1;
      };
      _this2.size = function() {
        return _size;
      };
      _this2.indexOf = function(key) {
        return _map[key];
      };
      _this2.contains = function(key) {
        return typeof _map[key] != "undefined";
      };
      return _this2;
    };
    return _this;
  };
  var createDataURL = function(width, height, getPixel) {
    const gif = gifImage(width, height);
    for (let y = 0; y < height; y += 1) {
      for (let x = 0; x < width; x += 1) {
        gif.setPixel(x, y, getPixel(x, y));
      }
    }
    const b = byteArrayOutputStream();
    gif.write(b);
    const base64 = base64EncodeOutputStream();
    const bytes = b.toByteArray();
    for (let i = 0; i < bytes.length; i += 1) {
      base64.writeByte(bytes[i]);
    }
    base64.flush();
    return "data:image/gif;base64," + base64;
  };
  var qrcode_default = qrcode;
  var stringToBytes = qrcode.stringToBytes;

  // public/log-text.json
  var log_text_default = {
    _about: "Single source of truth for every label + description rendered into the protocol log. Templates use {placeholder} for dynamic values substituted at runtime. All references to the agent server are spelled 'Agent Server' (not 'AS') to avoid conflation with 'Access Server' elsewhere in the AAuth protocol. The person server is spelled 'Person Server' everywhere (including terse HTTP lines) for consistency.",
    sections: {
      bootstrap: "Bootstrap logs",
      bootstrap_resumed: "Bootstrap logs (resumed)",
      refresh: "Refresh logs",
      authorize: "Authorization logs",
      authorize_resumed: "Authorization logs (resumed)"
    },
    bootstrap: {
      generate_ephemeral: {
        label: "Agent: generate ephemeral key",
        description: "The agent creates a fresh signing keypair for this session. The private half never leaves this device, so tokens issued later are useless to anyone else."
      },
      ps_discovery_request: {
        label_template: "Agent \u2192 Person Server: GET {path}",
        label_resolved_template: "Agent \u2192 Person Server: GET {path} \u2192 {status}",
        label_error_network_template: "Agent \u2192 Person Server: GET {path} (network error)",
        description: "Before the agent can talk to your Person Server, it asks which URLs to use for bootstrap and for sending you to consent."
      },
      ps_bootstrap_request: {
        label_template: "Agent \u2192 Person Server: POST {path}",
        label_resolved_template: "Agent \u2192 Person Server: POST {path} \u2192 {status}",
        label_error_network_template: "Agent \u2192 Person Server: POST {path} (network error)",
        label_error_unexpected_template: "Agent \u2192 Person Server: POST {path} \u2192 {status} (unexpected)",
        description: "The agent tells your Person Server a new agent wants to connect. The Person Server replies with a URL to show you for approval, plus one the agent can check for your decision."
      },
      ps_pending_longpoll: {
        label_template: "Agent \u2192 Person Server: GET {path} (long-poll)",
        label_resolved_template: "Agent \u2192 Person Server: GET {path} \u2192 {status}",
        label_resolved_no_token_template: "Agent \u2192 Person Server: GET {path} \u2192 200 (no bootstrap_token)",
        description: "The agent keeps one request open while you decide, instead of polling every second. The Person Server answers the moment you approve or deny."
      },
      ps_consent_prompt: {
        label: "User at Person Server: consent prompt",
        description: "Your Person Server asks if you trust this agent. Approve here on this device, or scan the QR to approve on another.",
        label_resolved_success: "User Consent Completed",
        label_resolved_denied: "Consent Denied",
        label_resolved_timed_out: "Consent Timed Out",
        label_resolved_no_token: "Pending returned no bootstrap_token"
      },
      ps_bootstrap_token_received: {
        label: "Person Server response: bootstrap_token received",
        description: "Once you approve, the Person Server hands the agent a short-lived, single-use ticket proving you said yes \u2014 the agent redeems it with its own Agent Server next."
      },
      ps_pending_bad_response: {
        label: "Bad /pending response",
        description: "The Person Server replied in a shape the agent didn't expect, so the bootstrap can't continue."
      },
      ps_user_denied: {
        label: "User denied consent",
        description: ""
      },
      ps_interaction_timed_out: {
        label: "Interaction timed out",
        description: "You didn't approve or deny in time, so the Person Server gave up waiting."
      },
      agent_server_challenge_request: {
        label_template: "Agent \u2192 Agent Server: POST {path}",
        label_resolved_template: "Agent \u2192 Agent Server: POST {path} \u2192 {status}",
        label_error_network_template: "Agent \u2192 Agent Server: POST {path} (network error)",
        description: "The agent shows the Person Server's ticket to its Agent Server, which asks for a WebAuthn ceremony to confirm a real human is here."
      },
      webauthn_ceremony_failed: {
        label: "WebAuthn ceremony failed",
        description: "The WebAuthn step didn't complete \u2014 likely cancelled, timed out, or the credential wasn't accepted."
      },
      webauthn_ceremony_success: {
        label: "User at Browser: WebAuthn ceremony",
        description: "You complete the WebAuthn ceremony to sign the challenge, proving a human is present and the right credential is on this device."
      },
      agent_server_verify_request: {
        label_template: "Agent \u2192 Agent Server: POST {path}",
        label_resolved_template: "Agent \u2192 Agent Server: POST {path} \u2192 {status}",
        label_error_network_template: "Agent \u2192 Agent Server: POST {path} (network error)",
        description: "The Agent Server verifies your WebAuthn response and remembers the pairing of you, this Person Server, and this device \u2014 so future refreshes skip the Person Server."
      }
    },
    bootstrap_resumed: {
      ps_consent_prompt: {
        label: "User at Person Server: consent prompt (resumed)",
        description: "You returned mid-approval (page reload or redirect back from the Person Server). The agent picks up the same pending request instead of starting over."
      }
    },
    refresh: {
      cannot_refresh: {
        label: "Cannot refresh",
        description: "No saved key + token pair on this device, so there's nothing to refresh \u2014 a full bootstrap is needed."
      },
      stage_new_ephemeral: {
        label: "Agent: stage new ephemeral key",
        description: "The agent prepares a fresh keypair but doesn't use it yet. If the refresh fails for any reason, the old key and token still work."
      },
      agent_server_refresh_challenge_request: {
        label_template: "Agent \u2192 Agent Server: POST {path}",
        label_resolved_template: "Agent \u2192 Agent Server: POST {path} \u2192 {status}",
        label_error_network_template: "Agent \u2192 Agent Server: POST {path} (network error)",
        description: "The agent asks its Agent Server for a WebAuthn challenge, signed with the old key so the server knows it's the same agent as before."
      },
      webauthn_assertion_failed: {
        label: "WebAuthn assertion failed",
        description: "The WebAuthn step didn't complete \u2014 likely cancelled, timed out, or the credential wasn't accepted."
      },
      webauthn_ceremony_success: {
        label: "User at Browser: WebAuthn ceremony",
        description: "You complete the WebAuthn ceremony to sign the refresh challenge, proving the same human is still here on this device."
      },
      agent_server_refresh_verify_request: {
        label_template: "Agent \u2192 Agent Server: POST {path}",
        label_resolved_template: "Agent \u2192 Agent Server: POST {path} \u2192 {status}",
        label_error_network_template: "Agent \u2192 Agent Server: POST {path} (network error)",
        description: "The Agent Server verifies your response, swaps in the new key, and issues a fresh agent token \u2014 no trip back to your Person Server needed."
      }
    },
    authorize: {
      missing_context: {
        label: "Missing agent_token or ephemeral key",
        description: "The agent doesn't have an agent token or key yet \u2014 bootstrap has to finish first."
      },
      agent_server_authorize_request: {
        label_template: "Agent \u2192 Agent Server: POST {path}",
        label_resolved_template: "Agent \u2192 Agent Server: POST {path} \u2192 {status}",
        label_error_network_template: "Agent \u2192 Agent Server: POST {path} (network error)",
        description: "The agent asks its Agent Server for a resource token scoped to this Person Server and resource. The Agent Server signs it on the agent's behalf."
      },
      ps_token_request: {
        label_template: "Agent \u2192 Person Server: POST {path}",
        label_resolved_template: "Agent \u2192 Person Server: POST {path} \u2192 {status}",
        label_error_network_template: "Agent \u2192 Person Server: POST {path} (network error)",
        description: "The agent trades that resource token with your Person Server for an auth token. A 200 means you've already consented to this scope; 202 means the Person Server needs your approval for a new one."
      },
      ps_pending_longpoll: {
        label_template: "Agent \u2192 Person Server: GET {path} (long-poll)",
        label_resolved_template: "Agent \u2192 Person Server: GET {path} \u2192 {status}",
        description: "If new consent is needed, the agent keeps one request open while you decide, instead of polling. The Person Server responds the moment you approve or deny."
      },
      ps_consent_prompt: {
        label: "User at Person Server: consent prompt",
        description: "Your Person Server asks if this agent may use the new scope. Approve here, or scan the QR to approve on another device.",
        label_resolved_success: "Interaction Completed",
        label_resolved_denied: "Interaction Denied",
        label_resolved_timed_out: "Interaction Timed Out"
      },
      authorization_granted: {
        label: "Authorization Granted",
        description: ""
      },
      authorization_denied: {
        label: "Authorization Denied",
        description: ""
      },
      authorization_timed_out: {
        label: "Authorization Timed Out",
        description: ""
      }
    },
    authorize_resumed: {
      ps_consent_prompt: {
        label: "User at Person Server: consent prompt (resumed)",
        description: "You returned mid-approval for a scope upgrade. The agent picks up the same pending request instead of starting over."
      }
    },
    demo_api: {
      missing_key: {
        label: "Demo API Call Failed",
        description: "No signing key on this device \u2014 the demo call can't be signed, so it won't go out."
      },
      request: {
        label_template: "GET {path}",
        label_resolved_template: "GET {path} \u2192 {status}",
        label_error_network_template: "GET {path} (network error)",
        description: "The agent calls the resource's demo endpoint, signing the HTTP request with its private key and attaching the auth token. The server checks the signature matches the token, then checks the token's scope covers this endpoint."
      },
      success: {
        label: "Demo API Called",
        description: ""
      },
      failure: {
        label: "Demo API Call Failed",
        description: ""
      }
    },
    errors: {
      unhandled: {
        label: "Unhandled error",
        description: "Something went wrong that the flow wasn't expecting \u2014 check the console for details."
      }
    },
    ui: {
      another_request_button: "Another Authorization Request",
      approve_at_ps: {
        bootstrap_heading: "Approve this agent",
        authorize_heading: "Approve this authorization request",
        continue_label: "Continue at your Person Server to approve this agent",
        or_another_device: "OR scan QR code",
        copy_link_default: "Copy link",
        copy_link_copied: "Copied!"
      }
    }
  };

  // client/protocol.js
  var POLL_WAIT_SECONDS = 45;
  function copy(path) {
    return path.split(".").reduce((o, k) => o == null ? void 0 : o[k], log_text_default);
  }
  function fmt(template, vars = {}) {
    if (!template) return "";
    let out = template;
    for (const [k, v] of Object.entries(vars)) {
      out = out.split(`{${k}}`).join(String(v));
    }
    return out;
  }
  function desc(key) {
    const d = copy(`${key}.description`);
    return d ? `<p>${d}</p>` : "";
  }
  window.addEventListener("unhandledrejection", (ev) => {
    try {
      const msg = ev?.reason?.stack || ev?.reason?.message || String(ev?.reason);
      console.error("[aauth] unhandled rejection:", msg);
      showLog();
      addLogStep(
        copy("errors.unhandled.label"),
        "error",
        `<p style="color: var(--error); white-space: pre-wrap;">${escapeHtml(msg)}</p>`
      );
    } catch {
    }
  });
  function trace(label, extra) {
    try {
      console.log(`[aauth] ${label}`, extra ?? "");
    } catch {
    }
  }
  window.aauthSigFetch = async function aauthSigFetch(url, { method = "GET", headers = {}, body, jwt } = {}) {
    const keyPair = window.aauthEphemeral.get();
    if (!keyPair) throw new Error("no ephemeral key available to sign with");
    if (!jwt) throw new Error("jwt required for sig=jwt scheme");
    const signingKey = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const hasBody = body !== void 0 && body !== null;
    const components = hasBody ? ["@method", "@authority", "@path", "content-type", "signature-key"] : ["@method", "@authority", "@path", "signature-key"];
    const mergedHeaders = hasBody ? { "Content-Type": "application/json", ...headers } : { ...headers };
    return (0, import_httpsig.fetch)(url, {
      method,
      headers: mergedHeaders,
      body: hasBody ? body : void 0,
      signingKey,
      signingCryptoKey: keyPair.privateKey,
      signatureKey: { type: "jwt", jwt },
      components
    });
  };
  var __activeLogContainer = null;
  function setActiveLog(id) {
    const el = document.getElementById(id);
    if (el) __activeLogContainer = el;
  }
  function currentLog() {
    return __activeLogContainer || document.getElementById("protocol-log");
  }
  function clearLog() {
    const log = currentLog();
    if (!log) return;
    log.innerHTML = "";
    log.classList.add("hidden");
  }
  function showLog() {
    const log = currentLog();
    if (log) log.classList.remove("hidden");
  }
  function statusIndicatorHtml(status) {
    if (status === "pending") {
      return '<span class="step-status step-status-pending"><span class="dot"></span><span class="dot"></span><span class="dot"></span></span>';
    }
    if (status === "success") return '<span class="step-status step-status-success">\u2713</span>';
    return '<span class="step-status step-status-error">\u2717</span>';
  }
  var CHEVRON_SVG = `<svg class="section-chevron" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="3" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="m19.5 8.25-7.5 7.5-7.5-7.5"/></svg>`;
  var __copyIdCounter = 0;
  function nextCopyId() {
    return `copy-tgt-${++__copyIdCounter}`;
  }
  function isExpandable(content) {
    return !!content && !/<details[\s>]/i.test(content);
  }
  function addLogSection(title) {
    const log = currentLog();
    if (!log) return;
    showLog();
    const section = document.createElement("details");
    section.className = "log-section";
    section.open = true;
    const summary = document.createElement("summary");
    summary.className = "log-section-heading";
    summary.textContent = title;
    section.appendChild(summary);
    log.appendChild(section);
  }
  function currentSection(log) {
    const sections = log.querySelectorAll(":scope > details.log-section");
    return sections[sections.length - 1] || log;
  }
  function addLogStep(label, status, content) {
    const log = currentLog();
    if (!log) return null;
    showLog();
    const target = currentSection(log);
    const expandable = isExpandable(content);
    const step = expandable ? document.createElement("details") : document.createElement("div");
    step.className = `log-step section-group ${status}${expandable ? "" : " log-step-static"}`;
    if (expandable) step.open = true;
    const heading = document.createElement(expandable ? "summary" : "div");
    heading.className = "section-heading";
    heading.innerHTML = `<span class="step-label">${statusIndicatorHtml(status)}<span class="step-text">${label}</span></span>${expandable ? CHEVRON_SVG : ""}`;
    step.appendChild(heading);
    const body = document.createElement("div");
    body.className = "log-step-body";
    body.innerHTML = content;
    step.appendChild(body);
    target.appendChild(step);
    requestAnimationFrame(() => {
      step.scrollIntoView({ behavior: "smooth", block: "start" });
    });
    return step;
  }
  function resolveStep(step, status, label) {
    if (!step) return;
    const isStatic = step.classList.contains("log-step-static");
    step.className = `log-step section-group ${status}${isStatic ? " log-step-static" : ""}`;
    const statusEl = step.querySelector(".step-status");
    const textEl = step.querySelector(".step-text");
    if (statusEl) statusEl.outerHTML = statusIndicatorHtml(status);
    if (textEl) textEl.textContent = label;
  }
  function appendStepBody(step, html) {
    if (!step) return;
    const body = step.querySelector(".log-step-body");
    if (!body) return;
    body.insertAdjacentHTML("beforeend", html);
  }
  function anotherRequestButton() {
    return `<div class="log-actions"><button type="button" class="btn-outline js-scroll-authz">${escapeHtml(copy("ui.another_request_button"))}</button></div>`;
  }
  function tokenWrap(innerHtml, extraClass = "") {
    const id = nextCopyId();
    return `<div class="token-wrap">
    <button class="copy-btn copy-btn-float" type="button" data-copy-target="#${id}" aria-label="Copy"></button>
    <div class="token-display${extraClass ? " " + extraClass : ""}" id="${id}">${innerHtml}</div>
  </div>`;
  }
  function formatRequest(method, url, headers, body) {
    let inner = `${escapeHtml(method)} ${escapeHtml(url)}
`;
    if (headers) {
      for (const [k, v] of Object.entries(headers)) {
        inner += `${escapeHtml(k)}: ${escapeHtml(v)}
`;
      }
    }
    if (body) {
      inner += `
${renderJSON(body)}`;
    }
    return `<div class="token-label">Request</div>${tokenWrap(inner)}`;
  }
  function formatResponse(status, headers, body) {
    let inner = `HTTP ${status}
`;
    if (headers) {
      for (const [k, v] of Object.entries(headers)) {
        inner += `${escapeHtml(k)}: ${escapeHtml(v)}
`;
      }
    }
    if (body) {
      inner += `
${renderJSON(body)}`;
    }
    return `<div class="token-label">Response</div>${tokenWrap(inner)}`;
  }
  function formatToken(label, token, decoded) {
    return `
    <details class="section-group">
      <summary class="section-heading"><span>${escapeHtml(label)}</span>${CHEVRON_SVG}</summary>
      ${tokenWrap(renderEncodedJWT(token), "encoded")}
    </details>
    <details class="section-group" open>
      <summary class="section-heading"><span>Decoded</span>${CHEVRON_SVG}</summary>
      ${tokenWrap(renderJSON(decoded))}
    </details>
  `;
  }
  function formatAuthToken(token) {
    return `
    ${tokenWrap(renderEncodedJWT(token), "encoded")}
    <details class="section-group" open>
      <summary class="section-heading"><span>Decoded</span>${CHEVRON_SVG}</summary>
      ${tokenWrap(renderJSON(decodeJWTPayloadBrowser(token)))}
    </details>
  `;
  }
  function getSelectedIdentityScopes() {
    const checkboxes = document.querySelectorAll('#identity-scope-grid input[type="checkbox"]:checked');
    return Array.from(checkboxes).map((cb) => cb.value).join(" ");
  }
  function getSelectedResourceScopes() {
    const checkboxes = document.querySelectorAll('#resource-scope-grid input[type="checkbox"]:checked');
    return Array.from(checkboxes).map((cb) => cb.value).join(" ");
  }
  function getHints() {
    const hints = {};
    const fields = ["login-hint", "domain-hint", "provider-hint", "tenant"];
    for (const field of fields) {
      const enabled = document.querySelector(`.hint-enable[data-hint-for="${field}"]`)?.checked;
      if (!enabled) continue;
      const val = document.getElementById(field)?.value?.trim();
      if (val) {
        hints[field.replace("-", "_")] = val;
      }
    }
    return hints;
  }
  async function runBootstrap(psUrl, hints) {
    const agentServerOrigin = window.location.origin;
    addLogSection(copy("sections.bootstrap"));
    const { keyPair, publicJwk } = await window.aauthEphemeral.rotate();
    addLogStep(
      copy("bootstrap.generate_ephemeral.label"),
      "success",
      desc("bootstrap.generate_ephemeral") + tokenWrap(renderJSON({ kty: publicJwk.kty, crv: publicJwk.crv, x: publicJwk.x }))
    );
    const psMetadataUrl = `${psUrl.replace(/\/$/, "")}/.well-known/aauth-person.json`;
    const psMetaStep = addLogStep(
      fmt(copy("bootstrap.ps_discovery_request.label_template"), { path: new URL(psMetadataUrl).pathname }),
      "pending",
      desc("bootstrap.ps_discovery_request") + formatRequest("GET", psMetadataUrl, null, null)
    );
    let psMetadata;
    try {
      const psMetaRes = await fetch(psMetadataUrl);
      psMetadata = await psMetaRes.json();
      if (!psMetaRes.ok) {
        resolveStep(psMetaStep, "error", fmt(copy("bootstrap.ps_discovery_request.label_resolved_template"), { path: new URL(psMetadataUrl).pathname, status: psMetaRes.status }));
        appendStepBody(psMetaStep, formatResponse(psMetaRes.status, null, psMetadata));
        return false;
      }
      resolveStep(psMetaStep, "success", fmt(copy("bootstrap.ps_discovery_request.label_resolved_template"), { path: new URL(psMetadataUrl).pathname, status: 200 }));
      appendStepBody(psMetaStep, formatResponse(200, null, psMetadata));
    } catch (err) {
      resolveStep(psMetaStep, "error", fmt(copy("bootstrap.ps_discovery_request.label_error_network_template"), { path: new URL(psMetadataUrl).pathname }));
      appendStepBody(psMetaStep, `<p style="color: var(--error)">${escapeHtml(err.message)}</p>`);
      return false;
    }
    const bootstrapEndpoint = psMetadata.bootstrap_endpoint || `${psUrl.replace(/\/$/, "")}/bootstrap`;
    const psBootstrapBody = {
      agent_server: agentServerOrigin,
      // Force the consent screen on every bootstrap so the demo flow shows
      // the full UX even after a user has already bound an agent server.
      // Without this the PS silently re-mints from its live thumbprint
      // session (1h TTL) and the consent page never renders.
      prompt: "consent",
      ...hints
    };
    const psBootReqStep = addLogStep(
      fmt(copy("bootstrap.ps_bootstrap_request.label_template"), { path: new URL(bootstrapEndpoint).pathname }),
      "pending",
      desc("bootstrap.ps_bootstrap_request") + formatRequest("POST", bootstrapEndpoint, {
        "Content-Type": "application/json",
        "Signature-Input": 'sig=("@method" "@authority" "@path" "content-type" "signature-key");created=...',
        "Signature": "sig=:...:",
        "Signature-Key": `sig=hwk;kty="${publicJwk.kty}";crv="${publicJwk.crv}";x="${publicJwk.x}"`
      }, psBootstrapBody)
    );
    let psBootRes, psBootBody, pollUrl, interactionParams, responseHeaders = {};
    try {
      psBootRes = await (0, import_httpsig.fetch)(bootstrapEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(psBootstrapBody),
        signingKey: publicJwk,
        signingCryptoKey: keyPair.privateKey,
        signatureKey: { type: "hwk" },
        components: ["@method", "@authority", "@path", "content-type", "signature-key"]
      });
      for (const key of ["location", "retry-after", "aauth-requirement"]) {
        const v = psBootRes.headers.get(key);
        if (v) responseHeaders[key] = v;
      }
      try {
        psBootBody = await psBootRes.json();
      } catch {
        psBootBody = null;
      }
      pollUrl = psBootRes.headers.get("location") || psBootBody?.location || psBootBody?.pending_url;
      const reqHeader = psBootRes.headers.get("aauth-requirement") || "";
      const fromHeader = parseInteractionHeader(reqHeader);
      interactionParams = {
        requirement: fromHeader.requirement || psBootBody?.requirement,
        code: fromHeader.code || psBootBody?.code,
        url: fromHeader.url || psMetadata.interaction_endpoint || psBootBody?.interaction_url
      };
      const reqStatus = psBootRes.ok ? "success" : "error";
      resolveStep(psBootReqStep, reqStatus, fmt(copy("bootstrap.ps_bootstrap_request.label_resolved_template"), { path: new URL(bootstrapEndpoint).pathname, status: psBootRes.status }));
      appendStepBody(psBootReqStep, formatResponse(psBootRes.status, responseHeaders, psBootBody));
    } catch (err) {
      resolveStep(psBootReqStep, "error", fmt(copy("bootstrap.ps_bootstrap_request.label_error_network_template"), { path: new URL(bootstrapEndpoint).pathname }));
      appendStepBody(psBootReqStep, `<p style="color: var(--error)">${escapeHtml(err.message)}</p>`);
      return false;
    }
    if (psBootRes.status !== 202 || !pollUrl) {
      resolveStep(psBootReqStep, "error", fmt(copy("bootstrap.ps_bootstrap_request.label_error_unexpected_template"), { path: new URL(bootstrapEndpoint).pathname, status: psBootRes.status }));
      return false;
    }
    const absolutePollUrl = new URL(pollUrl, bootstrapEndpoint).href;
    const pollPath = new URL(absolutePollUrl).pathname;
    const pollStep = addLogStep(
      fmt(copy("bootstrap.ps_pending_longpoll.label_template"), { path: pollPath }),
      "pending",
      desc("bootstrap.ps_pending_longpoll") + formatRequest("GET", absolutePollUrl, {
        "Prefer": `wait=${POLL_WAIT_SECONDS}`,
        "Signature-Input": 'sig=("@method" "@authority" "@path" "signature-key");created=...',
        "Signature": "sig=:...:",
        "Signature-Key": `sig=hwk;kty="${publicJwk.kty}";crv="${publicJwk.crv}";x="${publicJwk.x}"`
      }, null)
    );
    const interactionStep = addLogStep(
      copy("bootstrap.ps_consent_prompt.label"),
      "pending",
      desc("bootstrap.ps_consent_prompt") + renderInteraction(interactionParams, absolutePollUrl)
    );
    savePendingBootstrap({
      pollUrl: absolutePollUrl,
      bootstrapEndpoint,
      psUrl
    });
    const pending = await pollForBootstrapToken(absolutePollUrl, keyPair, publicJwk, interactionStep, pollStep);
    trace("pollForBootstrapToken returned", pending ? { hasToken: !!pending.bootstrap_token } : null);
    if (!pending) return false;
    addLogStep(
      copy("bootstrap.ps_bootstrap_token_received.label"),
      "success",
      desc("bootstrap.ps_bootstrap_token_received") + formatToken("Bootstrap Token (aa-bootstrap+jwt)", pending.bootstrap_token, decodeJWTPayloadBrowser(pending.bootstrap_token))
    );
    return await completeAgentServerBootstrap(pending.bootstrap_token, publicJwk, keyPair, { psUrl });
  }
  var _bootstrapPollRunning = false;
  async function pollForBootstrapToken(absolutePollUrl, keyPair, publicJwk, interactionStep, pollStep) {
    if (_bootstrapPollRunning) return null;
    _bootstrapPollRunning = true;
    try {
      return await _pollForBootstrapTokenImpl(absolutePollUrl, keyPair, publicJwk, interactionStep, pollStep);
    } finally {
      _bootstrapPollRunning = false;
    }
  }
  async function _pollForBootstrapTokenImpl(absolutePollUrl, keyPair, publicJwk, interactionStep, pollStep) {
    const pollPath = new URL(absolutePollUrl).pathname;
    if (!pollStep) {
      pollStep = addLogStep(
        fmt(copy("bootstrap.ps_pending_longpoll.label_template"), { path: pollPath }),
        "pending",
        `<p>Agent waits for consent; <code>Prefer: wait=${POLL_WAIT_SECONDS}</code> holds the connection open so the PS can push state immediately instead of tight polling.</p>` + formatRequest("GET", absolutePollUrl, {
          "Prefer": `wait=${POLL_WAIT_SECONDS}`,
          "Signature-Input": 'sig=("@method" "@authority" "@path" "signature-key");created=...',
          "Signature": "sig=:...:",
          "Signature-Key": `sig=hwk;kty="${publicJwk.kty}";crv="${publicJwk.crv}";x="${publicJwk.x}"`
        }, null)
      );
    }
    while (true) {
      try {
        const res = await (0, import_httpsig.fetch)(absolutePollUrl, {
          method: "GET",
          headers: { Prefer: `wait=${POLL_WAIT_SECONDS}` },
          signingKey: publicJwk,
          signingCryptoKey: keyPair.privateKey,
          signatureKey: { type: "hwk" },
          components: ["@method", "@authority", "@path", "signature-key"]
        });
        if (res.status === 200) {
          trace("poll 200 received");
          clearPendingBootstrap();
          const body = await res.json().catch(() => null);
          const token = body?.bootstrap_token;
          if (!token) {
            trace("poll 200 missing bootstrap_token", body);
            resolveStep(pollStep, "error", fmt(copy("bootstrap.ps_pending_longpoll.label_resolved_no_token_template"), { path: pollPath }));
            resolveStep(interactionStep, "error", "Pending returned no bootstrap_token");
            addLogStep(copy("bootstrap.ps_pending_bad_response.label"), "error", desc("bootstrap.ps_pending_bad_response") + formatResponse(200, null, body));
            return null;
          }
          trace("poll token extracted, length", token.length);
          resolveStep(pollStep, "success", fmt(copy("bootstrap.ps_pending_longpoll.label_resolved_template"), { path: pollPath, status: 200 }));
          resolveStep(interactionStep, "success", "User Consent Completed");
          return { bootstrap_token: token, raw: body };
        }
        if (res.status === 403) {
          clearPendingBootstrap();
          resolveStep(pollStep, "error", fmt(copy("bootstrap.ps_pending_longpoll.label_resolved_template"), { path: pollPath, status: 403 }));
          resolveStep(interactionStep, "error", "Consent Denied");
          addLogStep(
            copy("bootstrap.ps_user_denied.label"),
            "error",
            formatResponse(403, null, await res.json().catch(() => null)) + anotherRequestButton()
          );
          return null;
        }
        if (res.status === 404) {
          clearPendingBootstrap();
          resolveStep(pollStep, "error", fmt(copy("bootstrap.ps_pending_longpoll.label_resolved_template"), { path: pollPath, status: 404 }));
          resolveStep(interactionStep, "error", "Interaction Expired");
          addLogStep(
            "Interaction expired",
            "error",
            formatResponse(404, null, await res.json().catch(() => null)) + anotherRequestButton()
          );
          return null;
        }
        if (res.status === 408) {
          clearPendingBootstrap();
          resolveStep(pollStep, "error", fmt(copy("bootstrap.ps_pending_longpoll.label_resolved_template"), { path: pollPath, status: 408 }));
          resolveStep(interactionStep, "error", "Consent Timed Out");
          addLogStep(
            copy("bootstrap.ps_interaction_timed_out.label"),
            "error",
            desc("bootstrap.ps_interaction_timed_out") + formatResponse(408, null, null) + anotherRequestButton()
          );
          return null;
        }
      } catch (err) {
        console.log("Bootstrap poll error:", err.message);
        await new Promise((r) => setTimeout(r, 5e3));
      }
    }
  }
  async function completeAgentServerBootstrap(bootstrapToken, publicJwk, keyPair, ctx = {}) {
    trace("completeAgentServerBootstrap entered");
    clearPendingBootstrap();
    const agentLocal = window.aauthGetOrGenerateAgentName();
    const challengeEndpoint = `${window.location.origin}/bootstrap/challenge`;
    const challengeBody = { bootstrap_token: bootstrapToken, ephemeral_jwk: publicJwk, agent_local: agentLocal };
    const challengeReqStep = addLogStep(
      fmt(copy("bootstrap.agent_server_challenge_request.label_template"), { path: new URL(challengeEndpoint).pathname }),
      "pending",
      desc("bootstrap.agent_server_challenge_request") + formatRequest("POST", challengeEndpoint, {
        "Content-Type": "application/json",
        "Signature-Input": 'sig=("@method" "@authority" "@path" "content-type" "signature-key");created=...',
        "Signature": "sig=:...:",
        "Signature-Key": `sig=jwt;jwt="${bootstrapToken.substring(0, 20)}..."`
      }, {
        bootstrap_token: bootstrapToken.substring(0, 20) + "...",
        ephemeral_jwk: publicJwk,
        agent_local: agentLocal
      })
    );
    let challengeData;
    try {
      const res = await (0, import_httpsig.fetch)(challengeEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(challengeBody),
        signingKey: publicJwk,
        signingCryptoKey: keyPair.privateKey,
        signatureKey: { type: "jwt", jwt: bootstrapToken },
        components: ["@method", "@authority", "@path", "content-type", "signature-key"]
      });
      challengeData = await res.json();
      if (!res.ok) {
        resolveStep(challengeReqStep, "error", fmt(copy("bootstrap.agent_server_challenge_request.label_resolved_template"), { path: "/bootstrap/challenge", status: res.status }));
        appendStepBody(challengeReqStep, formatResponse(res.status, null, challengeData));
        return false;
      }
      resolveStep(challengeReqStep, "success", fmt(copy("bootstrap.agent_server_challenge_request.label_resolved_template"), { path: "/bootstrap/challenge", status: 200 }));
      appendStepBody(challengeReqStep, formatResponse(200, null, challengeData));
    } catch (err) {
      resolveStep(challengeReqStep, "error", fmt(copy("bootstrap.agent_server_challenge_request.label_error_network_template"), { path: "/bootstrap/challenge" }));
      appendStepBody(challengeReqStep, `<p style="color: var(--error)">${escapeHtml(err.message)}</p>`);
      return false;
    }
    let webauthnResponse;
    try {
      const opts = challengeData.webauthn_options;
      if (challengeData.webauthn_type === "register") {
        const parsed = window.aauthWebAuthn.parseCreationOptions(opts);
        const cred = await navigator.credentials.create({ publicKey: parsed });
        webauthnResponse = window.aauthWebAuthn.serializeCredential(cred);
      } else {
        const parsed = window.aauthWebAuthn.parseRequestOptions(opts);
        const cred = await navigator.credentials.get({ publicKey: parsed });
        webauthnResponse = window.aauthWebAuthn.serializeAssertion(cred);
      }
    } catch (err) {
      addLogStep(
        copy("bootstrap.webauthn_ceremony_failed.label"),
        "error",
        desc("bootstrap.webauthn_ceremony_failed") + `<p style="color: var(--error)">${escapeHtml(err.message)}</p>`
      );
      return false;
    }
    addLogStep(
      copy("bootstrap.webauthn_ceremony_success.label"),
      "success",
      desc("bootstrap.webauthn_ceremony_success")
    );
    const verifyEndpoint = `${window.location.origin}/bootstrap/verify`;
    const verifyBody = {
      bootstrap_tx_id: challengeData.bootstrap_tx_id,
      webauthn_response: webauthnResponse
    };
    const verifyStep = addLogStep(
      fmt(copy("bootstrap.agent_server_verify_request.label_template"), { path: new URL(verifyEndpoint).pathname }),
      "pending",
      desc("bootstrap.agent_server_verify_request") + formatRequest("POST", verifyEndpoint, {
        "Content-Type": "application/json",
        "Signature-Input": 'sig=("@method" "@authority" "@path" "content-type" "signature-key");created=...',
        "Signature": "sig=:...:",
        "Signature-Key": `sig=jwt;jwt="${bootstrapToken.substring(0, 20)}..."`
      }, {
        bootstrap_tx_id: challengeData.bootstrap_tx_id,
        webauthn_response: "(credential)"
      })
    );
    let result;
    try {
      const res = await (0, import_httpsig.fetch)(verifyEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(verifyBody),
        signingKey: publicJwk,
        signingCryptoKey: keyPair.privateKey,
        signatureKey: { type: "jwt", jwt: bootstrapToken },
        components: ["@method", "@authority", "@path", "content-type", "signature-key"]
      });
      result = await res.json();
      if (!res.ok) {
        resolveStep(verifyStep, "error", fmt(copy("bootstrap.agent_server_verify_request.label_resolved_template"), { path: "/bootstrap/verify", status: res.status }));
        appendStepBody(verifyStep, formatResponse(res.status, null, result));
        return false;
      }
      resolveStep(verifyStep, "success", fmt(copy("bootstrap.agent_server_verify_request.label_resolved_template"), { path: "/bootstrap/verify", status: 200 }));
    } catch (err) {
      resolveStep(verifyStep, "error", fmt(copy("bootstrap.agent_server_verify_request.label_error_network_template"), { path: "/bootstrap/verify" }));
      appendStepBody(verifyStep, `<p style="color: var(--error)">${escapeHtml(err.message)}</p>`);
      return false;
    }
    const bootstrapPayload = decodeJWTPayloadBrowser(bootstrapToken) || {};
    const bindingKey = await deriveBindingKeyBrowser(result.ps, bootstrapPayload.sub || "");
    window.aauthBinding.saveBinding({
      binding_key: bindingKey,
      ps_url: result.ps,
      user_sub: bootstrapPayload.sub || ""
    });
    window.aauthApplyBootstrapResult(result);
    appendStepBody(verifyStep, formatToken("Agent Token (aa-agent+jwt)", result.agent_token, decodeJWTPayloadBrowser(result.agent_token)));
    return { result };
  }
  async function deriveBindingKeyBrowser(psUrl, userSub) {
    const data = new TextEncoder().encode(`${psUrl}|${userSub}`);
    const hash = await crypto.subtle.digest("SHA-256", data);
    const bytes = new Uint8Array(hash);
    let binary = "";
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  async function runRefresh() {
    const { bindingKey } = window.aauthBinding.get();
    if (!bindingKey) return null;
    const oldKeyPair = window.aauthEphemeral.get();
    const agentToken = localStorage.getItem("aauth-agent-token");
    if (!oldKeyPair || !agentToken) {
      addLogStep(
        copy("refresh.cannot_refresh.label"),
        "error",
        desc("refresh.cannot_refresh")
      );
      return null;
    }
    addLogSection(copy("sections.refresh"));
    const { publicJwk: newPublicJwk } = await window.aauthEphemeral.stage();
    addLogStep(
      copy("refresh.stage_new_ephemeral.label"),
      "success",
      desc("refresh.stage_new_ephemeral") + tokenWrap(renderJSON({ kty: newPublicJwk.kty, crv: newPublicJwk.crv, x: newPublicJwk.x }))
    );
    const oldSigningJwk = await crypto.subtle.exportKey("jwk", oldKeyPair.publicKey);
    const refreshChallengeEndpoint = `${window.location.origin}/refresh/challenge`;
    const refreshChallengeBody = { binding_key: bindingKey, new_ephemeral_jwk: newPublicJwk };
    const reqStep = addLogStep(
      fmt(copy("refresh.agent_server_refresh_challenge_request.label_template"), { path: new URL(refreshChallengeEndpoint).pathname }),
      "pending",
      desc("refresh.agent_server_refresh_challenge_request") + formatRequest("POST", refreshChallengeEndpoint, {
        "Content-Type": "application/json",
        "Signature-Input": 'sig=("@method" "@authority" "@path" "content-type" "signature-key");created=...',
        "Signature": "sig=:...:",
        "Signature-Key": `sig=jwt;jwt="${agentToken?.substring(0, 20)}..."`
      }, refreshChallengeBody)
    );
    let challengeData;
    try {
      const res = await (0, import_httpsig.fetch)(refreshChallengeEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(refreshChallengeBody),
        signingKey: oldSigningJwk,
        signingCryptoKey: oldKeyPair.privateKey,
        signatureKey: { type: "jwt", jwt: agentToken },
        components: ["@method", "@authority", "@path", "content-type", "signature-key"]
      });
      challengeData = await res.json();
      if (!res.ok) {
        resolveStep(reqStep, "error", fmt(copy("refresh.agent_server_refresh_challenge_request.label_resolved_template"), { path: "/refresh/challenge", status: res.status }));
        appendStepBody(reqStep, formatResponse(res.status, null, challengeData));
        window.aauthEphemeral.discardStaged();
        window.aauthBinding.clearBinding();
        return null;
      }
      resolveStep(reqStep, "success", fmt(copy("refresh.agent_server_refresh_challenge_request.label_resolved_template"), { path: "/refresh/challenge", status: 200 }));
      appendStepBody(reqStep, formatResponse(200, null, challengeData));
    } catch (err) {
      resolveStep(reqStep, "error", fmt(copy("refresh.agent_server_refresh_challenge_request.label_error_network_template"), { path: "/refresh/challenge" }));
      appendStepBody(reqStep, `<p style="color: var(--error)">${escapeHtml(err.message)}</p>`);
      window.aauthEphemeral.discardStaged();
      return null;
    }
    let webauthnResponse;
    try {
      const parsed = window.aauthWebAuthn.parseRequestOptions(challengeData.webauthn_options);
      const cred = await navigator.credentials.get({ publicKey: parsed });
      webauthnResponse = window.aauthWebAuthn.serializeAssertion(cred);
    } catch (err) {
      addLogStep(
        copy("refresh.webauthn_assertion_failed.label"),
        "error",
        desc("refresh.webauthn_assertion_failed") + `<p style="color: var(--error)">${escapeHtml(err.message)}</p>`
      );
      window.aauthEphemeral.discardStaged();
      return null;
    }
    addLogStep(
      copy("refresh.webauthn_ceremony_success.label"),
      "success",
      desc("refresh.webauthn_ceremony_success")
    );
    const refreshVerifyEndpoint = `${window.location.origin}/refresh/verify`;
    const refreshVerifyBody = {
      refresh_tx_id: challengeData.refresh_tx_id,
      webauthn_response: webauthnResponse
    };
    const verifyStep = addLogStep(
      fmt(copy("refresh.agent_server_refresh_verify_request.label_template"), { path: new URL(refreshVerifyEndpoint).pathname }),
      "pending",
      desc("refresh.agent_server_refresh_verify_request") + formatRequest("POST", refreshVerifyEndpoint, {
        "Content-Type": "application/json",
        "Signature-Input": 'sig=("@method" "@authority" "@path" "content-type" "signature-key");created=...',
        "Signature": "sig=:...:",
        "Signature-Key": `sig=jwt;jwt="${agentToken?.substring(0, 20)}..."`
      }, {
        refresh_tx_id: challengeData.refresh_tx_id,
        webauthn_response: "(assertion)"
      })
    );
    let result;
    try {
      const res = await (0, import_httpsig.fetch)(refreshVerifyEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(refreshVerifyBody),
        signingKey: oldSigningJwk,
        signingCryptoKey: oldKeyPair.privateKey,
        signatureKey: { type: "jwt", jwt: agentToken },
        components: ["@method", "@authority", "@path", "content-type", "signature-key"]
      });
      result = await res.json();
      if (!res.ok) {
        resolveStep(verifyStep, "error", fmt(copy("refresh.agent_server_refresh_verify_request.label_resolved_template"), { path: "/refresh/verify", status: res.status }));
        appendStepBody(verifyStep, formatResponse(res.status, null, result));
        window.aauthEphemeral.discardStaged();
        return null;
      }
      resolveStep(verifyStep, "success", fmt(copy("refresh.agent_server_refresh_verify_request.label_resolved_template"), { path: "/refresh/verify", status: 200 }));
    } catch (err) {
      resolveStep(verifyStep, "error", fmt(copy("refresh.agent_server_refresh_verify_request.label_error_network_template"), { path: "/refresh/verify" }));
      appendStepBody(verifyStep, `<p style="color: var(--error)">${escapeHtml(err.message)}</p>`);
      window.aauthEphemeral.discardStaged();
      return null;
    }
    await window.aauthEphemeral.commitStaged();
    window.aauthApplyBootstrapResult(result);
    appendStepBody(verifyStep, formatToken("Agent Token (aa-agent+jwt)", result.agent_token, decodeJWTPayloadBrowser(result.agent_token)));
    return result;
  }
  async function startBootstrap() {
    const psUrl = (window.getCurrentPS?.() || "").trim();
    if (!psUrl) {
      alert("Please choose or enter a Person Server URL");
      return;
    }
    setActiveLog("bootstrap-log");
    clearLog();
    showLog();
    const hints = getHints();
    window.aauthBinding.clearBinding();
    localStorage.removeItem("aauth-agent-token");
    window.aauthUI?.setUnauthenticated?.();
    await runBootstrap(psUrl, hints);
  }
  async function startAuthorize() {
    const { bindingKey, bindingPs } = window.aauthBinding.get();
    if (!bindingKey || !bindingPs) {
      alert("No agent binding found. Bootstrap first.");
      return;
    }
    const combined = getCombinedScope();
    if (!combined) {
      alert("Select at least one scope");
      return;
    }
    setActiveLog("authz-log");
    clearLog();
    showLog();
    document.querySelector("#authz-section .authz-actions")?.classList.add("hidden");
    const hints = getHints();
    let agentTokenValid = false;
    const savedAgentToken = localStorage.getItem("aauth-agent-token");
    if (savedAgentToken) {
      try {
        const p = decodeJWTPayloadBrowser(savedAgentToken);
        agentTokenValid = p && p.exp > Math.floor(Date.now() / 1e3);
      } catch {
      }
    }
    if (!agentTokenValid) {
      const refreshed = await runRefresh();
      if (!refreshed) return;
    }
    await runAuthorizationAgainstPS(bindingPs, combined, hints);
  }
  function getCombinedScope() {
    const identity = (getSelectedIdentityScopes() || "").split(/\s+/).filter(Boolean);
    const resource = (getSelectedResourceScopes() || "").split(/\s+/).filter(Boolean);
    const all = Array.from(/* @__PURE__ */ new Set([...identity, ...resource]));
    return all.join(" ");
  }
  async function runAuthorizationAgainstPS(psUrl, scope, hints) {
    const keyPair = window.aauthEphemeral.get();
    const agentToken = localStorage.getItem("aauth-agent-token");
    if (!agentToken || !keyPair) {
      addLogStep(
        copy("authorize.missing_context.label"),
        "error",
        desc("authorize.missing_context")
      );
      return;
    }
    addLogSection(copy("sections.authorize"));
    const authzEndpoint = `${window.location.origin}/authorize`;
    const authzBody = { ps: psUrl, scope };
    const signingJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const authzReqStep = addLogStep(
      fmt(copy("authorize.agent_server_authorize_request.label_template"), { path: new URL(authzEndpoint).pathname }),
      "pending",
      desc("authorize.agent_server_authorize_request") + formatRequest("POST", authzEndpoint, {
        "Content-Type": "application/json",
        "Signature-Input": 'sig=("@method" "@authority" "@path" "content-type" "signature-key");created=...',
        "Signature": "sig=:...:",
        "Signature-Key": `sig=jwt;jwt="${agentToken?.substring(0, 20)}..."`
      }, authzBody)
    );
    let authzData;
    try {
      const res = await (0, import_httpsig.fetch)(authzEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(authzBody),
        signingKey: signingJwk,
        signingCryptoKey: keyPair.privateKey,
        signatureKey: { type: "jwt", jwt: agentToken },
        components: ["@method", "@authority", "@path", "content-type", "signature-key"]
      });
      authzData = await res.json();
      if (!res.ok) {
        resolveStep(authzReqStep, "error", fmt(copy("authorize.agent_server_authorize_request.label_resolved_template"), { path: "/authorize", status: res.status }));
        appendStepBody(authzReqStep, formatResponse(res.status, null, authzData));
        return;
      }
      resolveStep(authzReqStep, "success", fmt(copy("authorize.agent_server_authorize_request.label_resolved_template"), { path: "/authorize", status: 200 }));
    } catch (err) {
      resolveStep(authzReqStep, "error", fmt(copy("authorize.agent_server_authorize_request.label_error_network_template"), { path: "/authorize" }));
      appendStepBody(authzReqStep, `<p style="color: var(--error)">${escapeHtml(err.message)}</p>`);
      return;
    }
    appendStepBody(authzReqStep, formatToken("Resource Token (aa-resource+jwt)", authzData.resource_token, authzData.resource_token_decoded));
    const psMetadata = authzData.ps_metadata;
    const resourceToken = authzData.resource_token;
    const tokenEndpoint = psMetadata.token_endpoint;
    const psRequestBody = {
      resource_token: resourceToken,
      capabilities: ["interaction"],
      // Force the consent screen on every request so the demo flow shows
      // the full UX even when the PS would otherwise auto-release from a
      // cached binding (matches OIDC prompt=consent semantics).
      prompt: "consent",
      ...hints
    };
    const psReqStep = addLogStep(
      fmt(copy("authorize.ps_token_request.label_template"), { path: new URL(tokenEndpoint).pathname }),
      "pending",
      desc("authorize.ps_token_request") + formatRequest("POST", tokenEndpoint, {
        "Content-Type": "application/json",
        "Signature-Input": 'sig=("@method" "@authority" "@path" "signature-key");created=...',
        "Signature": "sig=:...:",
        "Signature-Key": `sig=jwt;jwt="${agentToken?.substring(0, 20)}..."`
      }, psRequestBody)
    );
    try {
      const signingJwk2 = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
      const psRes = await (0, import_httpsig.fetch)(tokenEndpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(psRequestBody),
        signingKey: signingJwk2,
        signingCryptoKey: keyPair.privateKey,
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
      const psPath = new URL(tokenEndpoint).pathname;
      resolveStep(psReqStep, psRes.ok ? "success" : "error", fmt(copy("authorize.ps_token_request.label_resolved_template"), { path: psPath, status: psRes.status }));
      if (psRes.status === 200 && psBody?.auth_token) {
        appendStepBody(psReqStep, formatResponse(psRes.status, responseHeaders, psBody));
        appendStepBody(psReqStep, formatAuthToken(psBody.auth_token) + anotherRequestButton());
      } else if (psRes.status === 202) {
        appendStepBody(psReqStep, formatResponse(psRes.status, responseHeaders, psBody));
        const reqHeader = psRes.headers.get("aauth-requirement") || "";
        const fromHeader = parseInteractionHeader(reqHeader);
        const interaction = {
          requirement: fromHeader.requirement || psBody?.requirement,
          code: fromHeader.code || psBody?.code,
          url: fromHeader.url || psMetadata.interaction_endpoint
        };
        const pollUrl = psRes.headers.get("location") || psBody?.location;
        let pollStep = null;
        if (pollUrl) {
          const absolutePollUrl = new URL(pollUrl, tokenEndpoint).href;
          const agentTokenForLog = localStorage.getItem("aauth-agent-token");
          pollStep = addLogStep(
            fmt(copy("authorize.ps_pending_longpoll.label_template"), { path: new URL(absolutePollUrl).pathname }),
            "pending",
            desc("authorize.ps_pending_longpoll") + formatRequest("GET", absolutePollUrl, {
              "Prefer": `wait=${POLL_WAIT_SECONDS}`,
              "Signature-Input": 'sig=("@method" "@authority" "@path" "signature-key");created=...',
              "Signature": "sig=:...:",
              "Signature-Key": `sig=jwt;jwt="${agentTokenForLog?.substring(0, 20)}..."`
            }, null)
          );
        }
        const interactionStep = addLogStep(
          copy("authorize.ps_consent_prompt.label"),
          "pending",
          desc("authorize.ps_consent_prompt") + renderInteraction(interaction, pollUrl, "authorize")
        );
        if (pollUrl) {
          savePendingAuthorize({
            pollUrl: new URL(pollUrl, tokenEndpoint).href,
            tokenEndpoint,
            psUrl,
            scope
          });
          startAuthTokenPolling(pollUrl, tokenEndpoint, interactionStep, pollStep);
        }
      } else {
        appendStepBody(psReqStep, formatResponse(psRes.status, responseHeaders, psBody));
      }
    } catch (err) {
      resolveStep(psReqStep, "error", fmt(copy("authorize.ps_token_request.label_error_network_template"), { path: new URL(tokenEndpoint).pathname }));
      appendStepBody(psReqStep, `<p style="color: var(--error)">${escapeHtml(err.message)}</p>`);
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
      if (val.startsWith('"') && val.endsWith('"')) val = val.slice(1, -1);
      result[key] = val;
    }
    return result;
  }
  function renderInteraction(interaction, pollUrl, kind = "bootstrap") {
    if (!interaction.url || !interaction.code) {
      const missing = [];
      if (!interaction.url) missing.push("interaction_endpoint (PS metadata) or url (header)");
      if (!interaction.code) missing.push("code");
      return `<p style="color: var(--muted);">Interaction required but missing: ${escapeHtml(missing.join(", "))}.</p>`;
    }
    const heading = kind === "authorize" ? copy("ui.approve_at_ps.authorize_heading") : copy("ui.approve_at_ps.bootstrap_heading");
    const callbackUrl = `${window.location.origin}/`;
    const sameDeviceUrl = `${interaction.url}?code=${encodeURIComponent(interaction.code)}&callback=${encodeURIComponent(callbackUrl)}`;
    const qrUrl = `${interaction.url}?code=${encodeURIComponent(interaction.code)}`;
    const qrId = `qr-${Math.random().toString(36).slice(2, 9)}`;
    const urlId = nextCopyId();
    const html = `
    <div class="interaction-box">
      <p class="interaction-heading">${escapeHtml(heading)}</p>
      <div class="interaction-actions">
        <a class="hello-btn hello-btn-black-on-dark" href="${escapeHtml(sameDeviceUrl)}">\u014D&nbsp;&nbsp;&nbsp;Continue with Hell\u014D</a>
      </div>
      <div class="interaction-or"><span>${escapeHtml(copy("ui.approve_at_ps.or_another_device"))}</span></div>
      <div class="qr-code" id="${qrId}"></div>
      <div class="interaction-url-row">
        <button class="copy-btn copy-link-text" type="button" data-copy="${escapeHtml(qrUrl)}">
          <span class="copy-link-text__default">Copy link</span>
          <span class="copy-link-text__copied">Copied!</span>
        </button>
      </div>
      <div class="interaction-approved" aria-hidden="true">
        <svg class="interaction-check" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="3" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" d="m4.5 12.75 6 6 9-13.5"/></svg>
      </div>
    </div>
  `;
    setTimeout(() => {
      const qrContainer = document.getElementById(qrId);
      if (!qrContainer) return;
      try {
        const qr = qrcode_default(0, "M");
        qr.addData(qrUrl);
        qr.make();
        qrContainer.innerHTML = qr.createSvgTag({ scalable: true, margin: 0 });
      } catch (err) {
        qrContainer.textContent = `(QR generation failed: ${err.message})`;
      }
    }, 0);
    return html;
  }
  var PENDING_KEY = "aauth-pending-bootstrap";
  function savePendingBootstrap(state) {
    try {
      localStorage.setItem(PENDING_KEY, JSON.stringify({ ...state, startedAt: Date.now() }));
    } catch {
    }
  }
  function clearPendingBootstrap() {
    try {
      localStorage.removeItem(PENDING_KEY);
    } catch {
    }
  }
  var _resumeInteractionPolling = false;
  async function resumePendingInteraction() {
    let saved;
    try {
      saved = JSON.parse(localStorage.getItem(PENDING_KEY) || "null");
    } catch {
      saved = null;
    }
    if (!saved?.pollUrl) return false;
    if (Date.now() - (saved.startedAt || 0) > 10 * 60 * 1e3) {
      clearPendingBootstrap();
      return false;
    }
    const kp = window.aauthEphemeral.get();
    if (!kp) {
      clearPendingBootstrap();
      return false;
    }
    if (_resumeInteractionPolling) return false;
    _resumeInteractionPolling = true;
    setActiveLog("bootstrap-log");
    showLog();
    addLogSection(copy("sections.bootstrap_resumed"));
    const publicJwk = await crypto.subtle.exportKey("jwk", kp.publicKey);
    const interactionStep = addLogStep(
      copy("bootstrap_resumed.ps_consent_prompt.label"),
      "pending",
      desc("bootstrap_resumed.ps_consent_prompt") + `<div class="token-display">Polling ${escapeHtml(saved.pollUrl)}</div>`
    );
    const pending = await pollForBootstrapToken(saved.pollUrl, kp, publicJwk, interactionStep);
    if (!pending) return true;
    addLogStep(
      copy("bootstrap.ps_bootstrap_token_received.label"),
      "success",
      desc("bootstrap.ps_bootstrap_token_received") + formatToken("Bootstrap Token (aa-bootstrap+jwt)", pending.bootstrap_token, decodeJWTPayloadBrowser(pending.bootstrap_token))
    );
    await completeAgentServerBootstrap(pending.bootstrap_token, publicJwk, kp, { psUrl: saved.psUrl });
    return true;
  }
  window.resumePendingInteraction = resumePendingInteraction;
  var PENDING_AUTHZ_KEY = "aauth-pending-authorize";
  function savePendingAuthorize(state) {
    try {
      localStorage.setItem(PENDING_AUTHZ_KEY, JSON.stringify({ ...state, startedAt: Date.now() }));
    } catch {
    }
  }
  function clearPendingAuthorize() {
    try {
      localStorage.removeItem(PENDING_AUTHZ_KEY);
    } catch {
    }
  }
  var _resumeAuthorizePolling = false;
  async function resumePendingAuthorize() {
    let saved;
    try {
      saved = JSON.parse(localStorage.getItem(PENDING_AUTHZ_KEY) || "null");
    } catch {
      saved = null;
    }
    if (!saved?.pollUrl) return false;
    if (Date.now() - (saved.startedAt || 0) > 10 * 60 * 1e3) {
      clearPendingAuthorize();
      return false;
    }
    const keyPair = window.aauthEphemeral.get();
    const agentToken = localStorage.getItem("aauth-agent-token");
    if (!keyPair || !agentToken) {
      clearPendingAuthorize();
      return false;
    }
    if (_resumeAuthorizePolling) return false;
    _resumeAuthorizePolling = true;
    setActiveLog("authz-log");
    showLog();
    addLogSection(copy("sections.authorize_resumed"));
    const interactionStep = addLogStep(
      copy("authorize_resumed.ps_consent_prompt.label"),
      "pending",
      desc("authorize_resumed.ps_consent_prompt") + `<div class="token-display">Polling ${escapeHtml(saved.pollUrl)}</div>`
    );
    startAuthTokenPolling(saved.pollUrl, saved.tokenEndpoint, interactionStep);
    return true;
  }
  window.resumePendingAuthorize = resumePendingAuthorize;
  function fireFallbackResume() {
    setTimeout(() => {
      try {
        window.resumePendingInteraction?.();
      } catch (err) {
        console.error("[aauth] fallback resumePendingInteraction threw:", err);
      }
      try {
        window.resumePendingAuthorize?.();
      } catch (err) {
        console.error("[aauth] fallback resumePendingAuthorize threw:", err);
      }
    }, 200);
  }
  if (document.readyState === "complete") {
    fireFallbackResume();
  } else {
    window.addEventListener("load", fireFallbackResume, { once: true });
  }
  var _authzPollRunning = false;
  async function startAuthTokenPolling(pollUrl, baseUrl, interactionStep, pollStep) {
    if (_authzPollRunning) return;
    _authzPollRunning = true;
    try {
      await _startAuthTokenPollingImpl(pollUrl, baseUrl, interactionStep, pollStep);
    } finally {
      _authzPollRunning = false;
    }
  }
  async function _startAuthTokenPollingImpl(pollUrl, baseUrl, interactionStep, pollStep) {
    const absolutePollUrl = new URL(pollUrl, baseUrl).href;
    const keyPair = window.aauthEphemeral.get();
    const agentToken = localStorage.getItem("aauth-agent-token");
    if (!keyPair || !agentToken) return;
    const signingJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const pollPath = new URL(absolutePollUrl).pathname;
    if (!pollStep) {
      pollStep = addLogStep(
        fmt(copy("authorize.ps_pending_longpoll.label_template"), { path: pollPath }),
        "pending",
        desc("authorize.ps_pending_longpoll") + formatRequest("GET", absolutePollUrl, {
          "Prefer": `wait=${POLL_WAIT_SECONDS}`,
          "Signature-Input": 'sig=("@method" "@authority" "@path" "signature-key");created=...',
          "Signature": "sig=:...:",
          "Signature-Key": `sig=jwt;jwt="${agentToken?.substring(0, 20)}..."`
        }, null)
      );
    }
    let cycle = 0;
    while (true) {
      cycle++;
      try {
        const res = await (0, import_httpsig.fetch)(absolutePollUrl, {
          method: "GET",
          headers: { Prefer: `wait=${POLL_WAIT_SECONDS}` },
          signingKey: signingJwk,
          signingCryptoKey: keyPair.privateKey,
          signatureKey: { type: "jwt", jwt: agentToken },
          components: ["@method", "@authority", "@path", "signature-key"]
        });
        const respHeaders = {};
        for (const key of ["retry-after", "aauth-requirement"]) {
          const v = res.headers.get(key);
          if (v) respHeaders[key] = v;
        }
        const body = await res.json().catch(() => null);
        appendStepBody(
          pollStep,
          `<details class="section-group"><summary class="section-heading"><span>Cycle ${cycle} \u2192 ${res.status}</span>${CHEVRON_SVG}</summary>${formatResponse(res.status, respHeaders, body)}</details>`
        );
        if (res.status === 200) {
          clearPendingAuthorize();
          resolveStep(pollStep, "success", fmt(copy("authorize.ps_pending_longpoll.label_resolved_template"), { path: pollPath, status: 200 }));
          resolveStep(interactionStep, "success", "Interaction Completed");
          addLogStep(
            copy("authorize.authorization_granted.label"),
            "success",
            (body?.auth_token ? formatAuthToken(body.auth_token) : "") + anotherRequestButton()
          );
          return;
        }
        if (res.status === 404) {
          clearPendingAuthorize();
          resolveStep(pollStep, "error", fmt(copy("authorize.ps_pending_longpoll.label_resolved_template"), { path: pollPath, status: 404 }));
          resolveStep(interactionStep, "error", "Interaction Expired");
          addLogStep(
            "Interaction expired",
            "error",
            formatResponse(404, null, body) + anotherRequestButton()
          );
          return;
        }
        if (res.status === 403 || res.status === 408) {
          clearPendingAuthorize();
          const label = res.status === 403 ? "Interaction Denied" : "Interaction Timed Out";
          resolveStep(pollStep, "error", fmt(copy("authorize.ps_pending_longpoll.label_resolved_template"), { path: pollPath, status: res.status }));
          resolveStep(interactionStep, "error", label);
          addLogStep(
            copy(res.status === 403 ? "authorize.authorization_denied.label" : "authorize.authorization_timed_out.label"),
            "error",
            formatResponse(res.status, null, body) + anotherRequestButton()
          );
          return;
        }
      } catch (err) {
        console.log("Poll error:", err.message);
        appendStepBody(
          pollStep,
          `<details class="section-group"><summary class="section-heading"><span>Cycle ${cycle} \u2192 network error</span>${CHEVRON_SVG}</summary><p style="color: var(--error)">${escapeHtml(err.message)}</p></details>`
        );
        await new Promise((r) => setTimeout(r, 5e3));
      }
    }
  }
  function decodeJWTPayloadBrowser(jwt) {
    try {
      const parts = jwt.split(".");
      return JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
    } catch {
      return null;
    }
  }
  document.getElementById("bootstrap-btn")?.addEventListener("click", startBootstrap);
  document.getElementById("authz-btn").addEventListener("click", startAuthorize);
  document.addEventListener("click", (e) => {
    const helloBtn = e.target.closest(".interaction-actions .hello-btn");
    if (helloBtn) helloBtn.classList.add("hello-btn-loader");
  });
  document.addEventListener("click", (e) => {
    const btn = e.target.closest(".js-scroll-authz");
    if (!btn) return;
    const section = document.getElementById("authz-section");
    if (section) section.scrollIntoView({ behavior: "smooth", block: "start" });
    setActiveLog("authz-log");
    setTimeout(clearLog, 300);
    document.querySelector("#authz-section .authz-actions")?.classList.remove("hidden");
  });
  async function callDemoResourceApi(authToken) {
    const endpoint = `${window.location.origin}/api/demo`;
    const keyPair = window.aauthEphemeral.get();
    if (!keyPair) {
      addLogStep(
        copy("demo_api.missing_key.label"),
        "error",
        desc("demo_api.missing_key")
      );
      return;
    }
    const reqStep = addLogStep(
      fmt(copy("demo_api.request.label_template"), { path: new URL(endpoint).pathname }),
      "pending",
      desc("demo_api.request") + formatRequest("GET", endpoint, {
        "Signature-Input": 'sig=("@method" "@authority" "@path" "signature-key");created=...',
        "Signature": "sig=:...:",
        "Signature-Key": `sig=jwt;jwt="${authToken?.substring(0, 20)}..."`
      }, null)
    );
    try {
      const signingJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
      const res = await (0, import_httpsig.fetch)(endpoint, {
        method: "GET",
        signingKey: signingJwk,
        signingCryptoKey: keyPair.privateKey,
        signatureKey: { type: "jwt", jwt: authToken },
        components: ["@method", "@authority", "@path", "signature-key"]
      });
      const body = await res.json().catch(() => null);
      resolveStep(reqStep, res.ok ? "success" : "error", fmt(copy("demo_api.request.label_resolved_template"), { path: "/api/demo", status: res.status }));
      addLogStep(
        copy(res.ok ? "demo_api.success.label" : "demo_api.failure.label"),
        res.ok ? "success" : "error",
        formatResponse(res.status, null, body) + anotherRequestButton()
      );
    } catch (err) {
      resolveStep(reqStep, "error", fmt(copy("demo_api.request.label_error_network_template"), { path: "/api/demo" }));
      addLogStep(
        copy("demo_api.failure.label"),
        "error",
        `<p style="color: var(--error)">${escapeHtml(err.message)}</p>` + anotherRequestButton()
      );
    }
  }
  window.aauthCallDemoResourceApi = callDemoResourceApi;
})();
