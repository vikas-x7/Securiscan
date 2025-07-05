import { scannerClient } from "@/server/core/http/scanner-client";
import { SecurityCheck, ScanTarget, FindingResult } from "@/types";
import { logger } from "@/server/core/logging/logger";

const log = logger.child("rate-limit-check");

/* ─── Rate Limit Header Variants ─── */
const RATE_LIMIT_HEADERS = [
    "x-ratelimit-limit",
    "x-rate-limit-limit",
    "ratelimit-limit",
    "x-ratelimit-remaining",
    "x-rate-limit-remaining",
    "ratelimit-remaining",
    "x-ratelimit-reset",
    "retry-after",
    "ratelimit-reset",
    "ratelimit",
    "x-ratelimit-policy",
];

export class RateLimitCheck implements SecurityCheck {
    name = "Rate Limiting & Resource Exhaustion Check";
    description = "Tests for missing rate limiting, DDoS protection, burst handling, and resource exhaustion vulnerabilities";
    owaspMapping = "Unrestricted Resource Consumption";
    owaspId = "API4:2023";

    async run(target: ScanTarget): Promise<FindingResult[]> {
        const findings: FindingResult[] = [];
        const hasRateLimit = target.requestsPerSecond && target.requestsPerSecond > 0;

        const testEndpoints = target.endpoints
            .filter((ep) => ["GET", "POST"].includes(ep.method.toUpperCase()))
            .slice(0, 4);

        const endpointTasks = testEndpoints.map(endpoint => async () => {
            const url = `${target.baseUrl}${endpoint.path}`;
            const method = endpoint.method.toLowerCase() as "get" | "post";
            const headers: Record<string, string> = { "User-Agent": "SecuriScan/1.0" };

            /* ── Phase 1: Graduated Burst Testing ── */
            const burstSizes = target.intensity === "AGGRESSIVE"
                ? [10, 25, 50]
                : target.intensity === "MEDIUM"
                    ? [10, 20]
                    : [5, 10];

            let wasRateLimited = false;
            const detectedRateLimitHeaders: Record<string, string> = {};

            for (const burstSize of burstSizes) {
                if (wasRateLimited) break;

                try {
                    const startTime = Date.now();

                    const requests = Array.from({ length: burstSize }, () =>
                        scannerClient({
                            requestsPerSecond: target.requestsPerSecond,
                            method,
                            url,
                            timeout: 10000,
                            validateStatus: () => true,
                            headers,
                            data: method === "post" ? {} : undefined,
                        }).catch(() => null)
                    );

                    const responses = await Promise.all(requests);
                    const elapsed = Date.now() - startTime;
                    const validResponses = responses.filter((r) => r !== null);
                    const rateLimited = validResponses.filter((r) => r!.status === 429);
                    const successful = validResponses.filter((r) => r!.status >= 200 && r!.status < 300);
                    const serverErrors = validResponses.filter((r) => r!.status >= 500);

                    const lastResponse = validResponses[validResponses.length - 1];
                    if (lastResponse) {
                        for (const header of RATE_LIMIT_HEADERS) {
                            const val = lastResponse.headers[header];
                            if (val) detectedRateLimitHeaders[header] = val;
                        }
                    }

                    if (rateLimited.length > 0) {
                        wasRateLimited = true;
                        const retryAfter = rateLimited[0]!.headers["retry-after"];

                        findings.push({
                            checkType: "rate_limiting",
                            severity: "INFO",
                            title: `Rate Limiting Active: ${endpoint.method} ${endpoint.path}`,
                            description: `Rate limiting is properly enforced. ${rateLimited.length}/${burstSize} requests were blocked with HTTP 429 after a burst of ${burstSize} requests in ${elapsed}ms.${retryAfter ? ` Retry-After: ${retryAfter}s.` : ""} This is good security practice.`,
                            evidence: {
                                request: { url, method: endpoint.method, headers },
                                response: {
                                    status: 429,
                                    headers: detectedRateLimitHeaders,
                                    body: { burstSize, rateLimitedRequests: rateLimited.length, successfulRequests: successful.length, elapsedMs: elapsed, retryAfter: retryAfter || null },
                                },
                                description: `Rate limiting triggered at burst size ${burstSize}`,
                            },
                            owaspMapping: this.owaspMapping,
                            owaspId: this.owaspId,
                            remediation: `Rate limiting is working correctly. Consider:\n- Implementing sliding window counters for smoother limits\n- Adding Retry-After header if not present\n- Using different limits for authenticated vs anonymous users`,
                            endpoint: endpoint.path,
                            method: endpoint.method,
                        });
                    }

                    if (serverErrors.length > burstSize * 0.3) {
                        findings.push({
                            checkType: "rate_limiting",
                            severity: "HIGH",
                            title: `Server Instability Under Load: ${endpoint.method} ${endpoint.path}`,
                            description: `A burst of ${burstSize} concurrent requests caused ${serverErrors.length} server errors (HTTP 5xx). The server cannot handle moderate concurrent load, indicating a resource exhaustion vulnerability. An attacker could easily DoS this endpoint.`,
                            evidence: {
                                request: { url, method: endpoint.method, headers },
                                response: { status: 500, headers: {}, body: { burstSize, successfulRequests: successful.length, serverErrors: serverErrors.length, elapsedMs: elapsed } },
                                description: `${serverErrors.length}/${burstSize} requests caused 5xx errors`,
                            },
                            owaspMapping: this.owaspMapping,
                            owaspId: this.owaspId,
                            remediation: `Improve server resilience:\n\n\`\`\`javascript\nconst pool = new Pool({ max: 20 });\n\napp.use((req, res, next) => {\n  req.setTimeout(5000, () => {\n    res.status(503).json({ error: 'Service temporarily unavailable' });\n  });\n  next();\n});\n\`\`\``,
                            endpoint: endpoint.path,
                            method: endpoint.method,
                        });
                    }
                } catch (err) {
                    log.debug(`Rate limit burst test failed for ${url}: ${err instanceof Error ? err.message : String(err)}`);
                }
            }

            /* ── Phase 2: No Rate Limiting Detected ── */
            if (!wasRateLimited && Object.keys(detectedRateLimitHeaders).length === 0) {
                const lastBurst = burstSizes[burstSizes.length - 1];
                findings.push({
                    checkType: "rate_limiting",
                    severity: "MEDIUM",
                    title: `No Rate Limiting: ${endpoint.method} ${endpoint.path}`,
                    description: `Sent ${lastBurst} rapid concurrent requests to ${endpoint.path} and NONE were rate-limited (HTTP 429). No rate-limit headers (X-RateLimit-*, Retry-After) were found. The endpoint is vulnerable to brute force attacks, credential stuffing, data scraping, and resource exhaustion.`,
                    evidence: {
                        request: { url, method: endpoint.method, headers },
                        response: { status: 200, headers: {}, body: { testedBurstSizes: burstSizes, rateLimitingDetected: false, rateLimitHeaders: "none" } },
                        description: `No rate limiting detected across ${burstSizes.length} burst tests (max: ${lastBurst} req)`,
                    },
                    owaspMapping: this.owaspMapping,
                    owaspId: this.owaspId,
                    remediation: `Implement rate limiting:\n\n\`\`\`javascript\nconst rateLimit = require('express-rate-limit');\n\nconst globalLimiter = rateLimit({\n  windowMs: 15 * 60 * 1000,\n  max: 100,\n  standardHeaders: true,\n  legacyHeaders: false,\n  message: { error: 'Too many requests' },\n});\n\napp.use('/api/', globalLimiter);\n\`\`\``,
                    endpoint: endpoint.path,
                    method: endpoint.method,
                });
            } else if (!wasRateLimited && Object.keys(detectedRateLimitHeaders).length > 0) {
                findings.push({
                    checkType: "rate_limiting",
                    severity: "LOW",
                    title: `Rate Limit Headers Present but Not Enforced: ${endpoint.method} ${endpoint.path}`,
                    description: `The endpoint includes rate limit headers (${Object.keys(detectedRateLimitHeaders).join(", ")}) but never returned HTTP 429 during burst testing. The rate limit may be set too high or only enforced at the infrastructure level (CDN/WAF). Verify that limits are actually enforced.`,
                    evidence: {
                        request: { url, method: endpoint.method, headers },
                        response: { status: 200, headers: detectedRateLimitHeaders, body: { headersPresent: true, enforced: false } },
                        description: `Rate limit headers present but not triggered`,
                    },
                    owaspMapping: this.owaspMapping,
                    owaspId: this.owaspId,
                    remediation: `Ensure rate limits are enforced, not just reported:\n\n\`\`\`javascript\nconst limiter = rateLimit({\n  windowMs: 60 * 1000,\n  max: 60,\n  standardHeaders: true,\n  handler: (req, res) => {\n    res.status(429).json({ error: 'Rate limit exceeded' });\n  },\n});\n\`\`\``,
                    endpoint: endpoint.path,
                    method: endpoint.method,
                });
            }

            /* ── Phase 3 + 4 in parallel ── */
            const phase3And4Tasks: (() => Promise<void>)[] = [];

            /* ── Phase 3: IP-Based Bypass Check ── */
            phase3And4Tasks.push(async () => {
                try {
                    const spoofResponse = await scannerClient({
                        requestsPerSecond: target.requestsPerSecond,
                        method: "get",
                        url,
                        timeout: 10000,
                        validateStatus: () => true,
                        headers: {
                            ...headers,
                            "X-Forwarded-For": "1.2.3.4",
                            "X-Real-IP": "5.6.7.8",
                            "X-Client-IP": "9.10.11.12",
                            "True-Client-IP": "13.14.15.16",
                        },
                    });

                    if (wasRateLimited && spoofResponse.status >= 200 && spoofResponse.status < 300) {
                        findings.push({
                            checkType: "rate_limiting",
                            severity: "HIGH",
                            title: `Rate Limit Bypass via IP Spoofing: ${endpoint.path}`,
                            description: `After being rate-limited, sending requests with spoofed IP headers (X-Forwarded-For, X-Real-IP) resulted in a successful response. The rate limiter trusts client-provided IP headers, allowing attackers to bypass limits by rotating spoofed IPs.`,
                            evidence: {
                                request: { url, method: "GET", headers: { "X-Forwarded-For": "1.2.3.4", "X-Real-IP": "5.6.7.8" } },
                                response: { status: spoofResponse.status, headers: spoofResponse.headers as Record<string, string> },
                                description: `IP spoofing bypassed rate limiting`,
                            },
                            owaspMapping: this.owaspMapping,
                            owaspId: this.owaspId,
                            remediation: `Use the actual connection IP, not client headers:\n\n\`\`\`javascript\nconst limiter = rateLimit({\n  keyGenerator: (req) => {\n    return req.connection.remoteAddress;\n  },\n});\n\napp.set('trust proxy', 1);\n\`\`\``,
                            endpoint: endpoint.path,
                            method: "GET",
                        });
                    }
                } catch {
                    // Skip
                }
            });

            /* ── Phase 4: Resource-Heavy Payload Check ── */
            if (endpoint.method.toUpperCase() === "POST") {
                phase3And4Tasks.push(async () => {
                    try {
                        const heavyPayload = JSON.stringify({ data: "X".repeat(1_000_000) });

                        const response = await scannerClient({
                            requestsPerSecond: target.requestsPerSecond,
                            method: "post",
                            url,
                            timeout: 15000,
                            validateStatus: () => true,
                            headers: { ...headers, "Content-Type": "application/json" },
                            data: heavyPayload,
                            maxBodyLength: Infinity,
                        });

                        if (response.status >= 200 && response.status < 300) {
                            findings.push({
                                checkType: "rate_limiting",
                                severity: "HIGH",
                                title: `No Request Size Limit: POST ${endpoint.path}`,
                                description: `The endpoint accepted a 1MB payload without rejection. No request body size limit is enforced, allowing attackers to exhaust server memory and disk space by sending oversized payloads.`,
                                evidence: {
                                    request: { url, method: "POST", headers: { "Content-Type": "application/json" } },
                                    response: { status: response.status, headers: response.headers as Record<string, string>, body: { payloadSize: "1MB", accepted: true } },
                                    description: `1MB payload accepted without size limit`,
                                },
                                owaspMapping: this.owaspMapping,
                                owaspId: this.owaspId,
                                remediation: `Set request body size limits:\n\n\`\`\`javascript\napp.use(express.json({ limit: '100kb' }));\napp.use(express.urlencoded({ limit: '100kb', extended: true }));\n\n// Nginx:\nclient_max_body_size 100k;\n\`\`\``,
                                endpoint: endpoint.path,
                                method: "POST",
                            });
                        }
                    } catch {
                        // Expected for properly limited endpoints
                    }
                });
            }

            if (!hasRateLimit) {
                await Promise.all(phase3And4Tasks.map(t => t()));
            } else {
                for (const task of phase3And4Tasks) {
                    await task();
                }
            }
        });

        if (!hasRateLimit) {
            await Promise.all(endpointTasks.map(t => t()));
        } else {
            for (const task of endpointTasks) {
                await task();
            }
        }

        return findings;
    }
}
