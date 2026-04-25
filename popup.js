// ============================================================
//  PHISHLY — popup.js
//  Handles the main input view and results view inside the popup.
// ============================================================

// ─── CONSTANTS ───────────────────────────────────────────────

const RISK       = { CLEAN: 0, LOW: 1, MODERATE: 2, HIGH: 3, CRITICAL: 4 };
const RISK_LABEL = ["Clean", "Low", "Moderate", "High", "Critical"];
const RISK_BADGE = ["badge-clean", "badge-low", "badge-moderate", "badge-high", "badge-critical"];
const RISK_COLOR = ["green", "green", "yellow", "orange", "red"];

const LOADING_MESSAGES = [
    "Analyzing sender...",
    "Checking links...",
    "Running AI analysis...",
    "Calculating risk score...",
];

const SIGNAL_WEIGHTS = {
    sender_api:                     { weight: 0.90 },
    sender_pattern:                 { weight: 0.45 },
    links_gsb:                      { weight: 1.00 },
    links_pattern:                  { weight: 0.50 },
    content_ai:                     { weight: 0.75 },
    content_pattern:                { weight: 0.40 },
    checkbox_unexpected_sender:     { weight: 0.65 },
    checkbox_asks_login:            { weight: 0.60 },
    checkbox_unexpected_attachment: { weight: 0.75 },
    checkbox_sensitive_info:        { weight: 0.55 },
    checkbox_urgent_language:       { weight: 0.30 },
    checkbox_qr_code:               { weight: 0.45 },
};

const HARD_OVERRIDES = [
    {
        id: "confirmed_malicious_link",
        condition: (ctx) => ctx.apiMaliciousLinkHit === true, // <-- Changed
        minimumRisk: RISK.CRITICAL,
    },
    {
        id: "disposable_on_new_domain",
        condition: (ctx) => ctx.disposableEmail === true && ctx.domainAgeDays !== null && ctx.domainAgeDays < 30,
        minimumRisk: RISK.HIGH,
    },
    {
        id: "verified_clean_sender",
        condition: (ctx) => ctx.senderSource === "API" && ctx.senderSeverity < 0.15,
        maximumRisk: RISK.MODERATE,
    },
    {
        id: "checkboxes_only",
        condition: (ctx) => ctx.senderSource === undefined &&
                            ctx.apiMaliciousLinkHit === undefined && // <-- Changed
                            ctx.senderSeverity === undefined,
        maximumRisk: RISK.LOW,
    },
    {
        id: "critical_only",
        condition: (ctx) => ctx.apiMaliciousLinkHit !== true,
        maximumRisk: RISK.HIGH,
    },
];

// ─── VIEW MANAGEMENT ─────────────────────────────────────────

function showView(viewId) {
    ["view-main", "view-loading", "view-results"].forEach(id => {
        document.getElementById(id).style.display = id === viewId ? "block" : "none";
    });
}

// ─── LOADING MESSAGES ────────────────────────────────────────

function cycleLoadingMessages() {
    let i = 0;
    return setInterval(() => {
        const el = document.getElementById("loading-message");
        if (el) el.textContent = LOADING_MESSAGES[i % LOADING_MESSAGES.length];
        i++;
    }, 1200);
}

// ─── SCORING ENGINE ──────────────────────────────────────────

function senderSeverity(r) {
    if (!r?.display || r.display.trim() === "") return null;
    return Math.min(r.score / r.maxScore, 1.0);
}

function linksSeverity(r) {
    if (!r || (r.links.length === 0 && r.score === 0)) return null;
    return Math.min(r.score / r.maxScore, 1.0);
}

function contentSeverity(aiResult, subjectResult, textResult, data) {
    const hasSubject = data.subjectChecked && data.subjectChecked.trim() !== "";
    const hasBody    = data.susTextsChecked && data.susTextsChecked.trim() !== "";
    if (!hasSubject && !hasBody) return null;
    if (aiResult?.probability !== undefined) return aiResult.probability;
    const patternScore = (subjectResult?.score ?? 0) + (textResult?.score ?? 0);
    return Math.min(patternScore / 30, 1.0);
}

function compoundEvidence(vals) {
    if (vals.length === 0) return 0;
    return 1 - vals.reduce((p, e) => p * (1 - Math.max(0, Math.min(1, e))), 1);
}

function weightedAverage(contribs) {
    const totalWeight = contribs.reduce((s, c) => s + c.weight, 0);
    if (totalWeight === 0) return 0;
    return contribs.reduce((s, c) => s + c.effectiveEvidence * c.weight, 0) / totalWeight;
}

function evidenceToRisk(score) {
    if (score < 0.15) return RISK.CLEAN;
    if (score < 0.35) return RISK.LOW;
    if (score < 0.60) return RISK.MODERATE;
    if (score < 0.80) return RISK.HIGH;
    return RISK.CRITICAL;
}

function buildCheckboxContributions(data) {
    const contributions     = [];
    const checkedSignals    = [];
    const highImpactSignals = [];

    if (data.unexpectedSenderChecked)    { contributions.push({ effectiveEvidence: 0.80, weight: SIGNAL_WEIGHTS.checkbox_unexpected_sender.weight });     checkedSignals.push("Unexpected sender");        highImpactSignals.push("you didn't expect this message"); }
    if (data.asksLoginChecked)           { contributions.push({ effectiveEvidence: 0.85, weight: SIGNAL_WEIGHTS.checkbox_asks_login.weight });            checkedSignals.push("Asks to login");            highImpactSignals.push("a request for your credentials"); }
    if (data.unexpectedAttachmentChecked){ contributions.push({ effectiveEvidence: 0.90, weight: SIGNAL_WEIGHTS.checkbox_unexpected_attachment.weight });  checkedSignals.push("Unexpected attachment");    highImpactSignals.push("an unverified attachment"); }
    if (data.sensititiveInfoChecked)     { contributions.push({ effectiveEvidence: 0.90, weight: SIGNAL_WEIGHTS.checkbox_sensitive_info.weight });        checkedSignals.push("Sensitive info requested"); highImpactSignals.push("a request for sensitive data"); }
    
    if (data.urgentChecked)              { contributions.push({ effectiveEvidence: 0.40, weight: SIGNAL_WEIGHTS.checkbox_urgent_language.weight });       checkedSignals.push("Urgent language"); }
    
    if (data.qrCodeChecked) { 
        contributions.push({ effectiveEvidence: 0.70, weight: SIGNAL_WEIGHTS.checkbox_qr_code.weight }); 
        checkedSignals.push("QR code present"); 
        highImpactSignals.push("a suspicious QR code"); 
    }

    return { contributions, checkedSignals, highImpactSignals };
}

function calculateScore({ senderResult, linksResult, aiResult, subjectResult, textResult, data }) {
    const contributions = [];
    const signalContext = {};
    let presentSignals  = 0;
    const totalSignals  = 4;

    const senderSev = senderSeverity(senderResult);
    if (senderSev !== null) {
        presentSignals++;
        const isApi      = senderResult.source === "API";
        const confidence = isApi ? 0.90 : 0.55;
        const weight     = isApi ? SIGNAL_WEIGHTS.sender_api.weight : SIGNAL_WEIGHTS.sender_pattern.weight;
        contributions.push({ effectiveEvidence: senderSev * confidence, weight });
        signalContext.senderSource    = senderResult.source;
        signalContext.senderSeverity  = senderSev;
        signalContext.disposableEmail = senderResult.flags?.some(f => f.toLowerCase().includes("disposable")) ?? false;
        signalContext.domainAgeDays   = senderResult.domainAge ?? null;
    }

    const linksSev = linksSeverity(linksResult);
    if (linksSev !== null) {
        presentSignals++;
        const isApi      = linksResult.source && linksResult.source.startsWith("API");
        const confidence = isApi ? 0.95 : 0.60;
        const weight     = isApi ? SIGNAL_WEIGHTS.links_gsb.weight : SIGNAL_WEIGHTS.links_pattern.weight;
        contributions.push({ effectiveEvidence: linksSev * confidence, weight });
        
        signalContext.apiMaliciousLinkHit = linksResult.links?.some(l =>
            l.linkFlags?.some(f => f.toLowerCase().includes("google safe browsing") || f.toLowerCase().includes("virustotal"))
        ) ?? false;
    }

    const contentSev = contentSeverity(aiResult, subjectResult, textResult, data);
    if (contentSev !== null) {
        presentSignals++;
        const isAi      = aiResult !== null && aiResult !== undefined;
        const confidence = isAi ? 0.75 : 0.45;
        const weight     = isAi ? SIGNAL_WEIGHTS.content_ai.weight : SIGNAL_WEIGHTS.content_pattern.weight;
        contributions.push({ effectiveEvidence: contentSev * confidence, weight });
    }

    const { contributions: cbContribs, checkedSignals, highImpactSignals } = buildCheckboxContributions(data);
    if (cbContribs.length > 0) {
        presentSignals++;
        const cbEvidence  = compoundEvidence(cbContribs.map(c => c.effectiveEvidence));
        const avgCbWeight = cbContribs.reduce((s, c) => s + c.weight, 0) / cbContribs.length;
        contributions.push({ effectiveEvidence: cbEvidence, weight: avgCbWeight });
    }

    const compoundedScore = compoundEvidence(contributions.map(c => c.effectiveEvidence));
    const weightedScore   = weightedAverage(contributions);
    const blendedScore    = (compoundedScore * 0.55) + (weightedScore * 0.45);

    let overallRisk        = evidenceToRisk(blendedScore);
    const appliedOverrides = [];

    for (const override of HARD_OVERRIDES) {
        if (override.condition(signalContext)) {
            appliedOverrides.push(override.id);
            if (override.minimumRisk !== undefined && overallRisk < override.minimumRisk) overallRisk = override.minimumRisk;
            if (override.maximumRisk !== undefined && overallRisk > override.maximumRisk) overallRisk = override.maximumRisk;
        }
    }

    return { overallRisk, score: blendedScore, presentSignals, totalSignals, checkedSignals, highImpactSignals, appliedOverrides };
}

function assessSender(r) {
    if (!r?.display || r.display.trim() === "") return null;
    return evidenceToRisk(senderSeverity(r));
}

function assessLinks(r) {
    if (!r) return null;
    if (r.links.length === 0 && r.score === 0) return RISK.CLEAN;
    
    if (r.links?.some(l => l.linkFlags?.some(f => f.toLowerCase().includes("google safe browsing") || f.toLowerCase().includes("virustotal")))) {
        return RISK.CRITICAL;
    }
    return evidenceToRisk(linksSeverity(r));
}

function assessContent(aiResult, subjectResult, textResult, data) {
    const sev = contentSeverity(aiResult, subjectResult, textResult, data);
    if (sev === null) return null;
    return evidenceToRisk(sev);
}

function buildCoverageSummary(senderResult, linksResult, aiResult, subjectResult, textResult, data) {
    const provided = [];
    const missing  = [];
    senderResult?.display?.trim()
        ? provided.push("Sender")
        : missing.push("Sender — add the email address or phone number");
    linksResult?.links?.length > 0 || data.susLinksChecked?.trim()
        ? provided.push("Links")
        : missing.push("Links — paste any links from the email");
    data.subjectChecked?.trim() || data.susTextsChecked?.trim()
        ? provided.push(aiResult ? "Content (AI)" : "Content (pattern-based)")
        : missing.push("Content — add the subject line and/or body text");
    return { provided, missing };
}

function generateSummary(scoreResult, senderRisk, linksRisk, contentRisk) {
    const { overallRisk, highImpactSignals, appliedOverrides } = scoreResult;
    const techFlags = [];
    if (senderRisk >= RISK.MODERATE) techFlags.push("a suspicious sender");
    if (linksRisk === RISK.CRITICAL) techFlags.push("confirmed malicious links");
    else if (linksRisk >= RISK.MODERATE) techFlags.push("suspicious links");
    if (contentRisk === RISK.CRITICAL) techFlags.push("highly suspicious message content");
    else if (contentRisk >= RISK.HIGH) techFlags.push("highly suspicious subject or body text");
    else if (contentRisk >= RISK.MODERATE) techFlags.push("moderately suspicious content");

    const fmt = (items) => {
        if (items.length === 0) return "";
        if (items.length === 1) return items[0];
        return items.slice(0, -1).join(", ") + " and " + items[items.length - 1];
    };

    const techNarrative  = fmt(techFlags);
    const humanNarrative = fmt(highImpactSignals);

    if (overallRisk === RISK.CLEAN) {
        return "No significant phishing signals were detected based on what you provided. Always trust your instincts — if something feels off, verify directly with the organization through their official website.";
    }
    if (overallRisk === RISK.LOW) {
        let s = "This email has a small number of signals worth noting. ";
        if (techNarrative) s += `We detected ${techNarrative}. `;
        s += "This alone is not necessarily cause for concern, but stay cautious and verify before taking any action.";
        return s;
    }
    if (overallRisk === RISK.MODERATE) {
        let s = "This email has some signals worth pausing on. ";
        if (techNarrative) s += `We detected ${techNarrative}, which is a pattern commonly seen in phishing. `;
        if (humanNarrative) s += techNarrative ? `You also indicated this email contained ${humanNarrative}. ` : `You indicated this email contained ${humanNarrative}. `;
        s += "We recommend verifying this message directly with the organization before taking any action.";
        return s;
    }
    let s = "This email has several characteristics commonly associated with phishing. ";
    if (techNarrative) s += `Our analysis detected ${techNarrative}. `;
    if (humanNarrative) s += `Crucially, your observation of ${humanNarrative} confirms this is a high-risk situation. `;
    if (appliedOverrides.includes("confirmed_malicious_link")) s += "A link in this message was confirmed malicious by threat intelligence database — do not click anything. ";
    s += "We strongly recommend not interacting with this message.";
    return s;
}

// ─── API CALLS ───────────────────────────────────────────────

async function checkAbstractEmail(email) {
    try {
        const r = await fetch("http://127.0.0.1:5001/verify-email", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ email }) });
        return await r.json();
    } catch (error) {
        console.error("Email API error:", error);
        return null;
    }
}

async function checkNumVerify(number) {
    try {
        const r = await fetch("http://127.0.0.1:5001/verify-phone", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ number })
    });
        return await r.json();
    } catch (error) {
        console.error("NumVerify API error:", error);
        return null;
    }
    
}

async function checkVirusTotal(links) {
    try {
        const r = await fetch("http://127.0.0.1:5001/check-url-vt", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ links }),
        });
        const data = await r.json();
        
        // If the backend signals a failure/rate-limit, return null to trigger GSB
        if (data.fallback) return null; 
        
        return data.matches || [];
    } catch (error) {
        console.error("VT proxy unreachable:", error);
        return null;
    }
}

async function checkGoogleSafeBrowsing(links) {
    try {
        const r = await fetch("http://127.0.0.1:5001/check-url", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ links }),
        });
        const data = await r.json();
        if (data.error) {
            console.error("GSB proxy error:", data.error);
            return null;
        }
        return data.matches?.length > 0 ? data.matches : [];
    } catch (error) {
        console.error("GSB proxy unreachable:", error);
        return null;
    }
}

async function callAIModel(subject, body) {
    try {
        const r    = await fetch("http://127.0.0.1:5001/predict", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ subject, body }) });
        const data = await r.json();
        return data;
    } catch (error) {
        console.error("AI Server unreachable:", error);
        return null;
    }
}

// ─── PATTERN ANALYZERS ───────────────────────────────────────

function detectSenderType(sender) {
    if (sender.includes("@")) return "email";
    if (/^[\d\s\+\-\(\)\.]{7,20}$/.test(sender)) return "phone";
    return "unknown";
}

function normalizeUrl(url) {
    if (!/^https?:\/\//i.test(url)) return "https://" + url;
    return url;
}

function runSenderPatterns(sender, result) {
    const tldMatch = sender.match(/\.(xyz|top|click|loan|work|gq|ml|cf|tk|zip|move)$/i);
    if (tldMatch) {
        result.score += 3;
        result.flags.push(`Unusual domain extension "${tldMatch[1]}" — commonly used in phishing`);
    }
 
    const brandMatch = sender.match(
        /payp[a@4][l1]|g[o0]{2}g[l1][e3]|micr[o0]s[o0]ft|[a@]pp?[l1][e3]|amaz[o0]n|netfl[i1]x|w[e3]ll[s$]farg[o0]|ch[a@][s$][e3]b[a@]nk|b[o0][f4][a@]/i
    );
    if (brandMatch) {
        result.score += 6; // was 3 — raised so spoofed senders reach MODERATE
        result.flags.push(`Possible brand spoofing detected — "${brandMatch[0]}" found in address`);
    }
 
    // Widened from /[0@](?=.*@)/ to catch more leet-substitution chars before the @
    const charMatch = sender.match(/[013$](?=[^@]*@)/);
    if (charMatch && !brandMatch) {
        result.score += 2; // was 1
        result.flags.push("Possible character substitution detected in sender address");
    }
 
    const domainMatch = sender.match(/@([\w.-]+)/);
    if (domainMatch && (domainMatch[1].match(/\./g) || []).length >= 3) {
        result.score += 2;
        result.flags.push(`Excessive subdomains detected — "${domainMatch[1]}"`);
    }
    const tldSuspicious = sender.match(/[-]{2,}|([a-z]+-){3,}/i);
    if (tldSuspicious) {
        result.score += 1;
        result.flags.push("Excessive hyphens in domain — common in spoofed addresses");
    }
    if (result.flags.length === 0) {
        result.flags.push("No obvious patterns detected — verify this domain manually");
    }
}

async function patternSender(sender) {
    const result = { score: 0, maxScore: 10, flags: [], display: sender };

    if (!sender || sender.trim() === "") {
        result.flags.push("No sender text provided — if the email has a sender, consider adding it for analysis");
        return result;
    }

    const senderType = detectSenderType(sender);

    if (senderType === "email") {
        const apiResult = await checkAbstractEmail(sender);
        if (apiResult) {
            result.source   = "API";
            result.maxScore = 20;
            if (apiResult.email_deliverability?.status === "UNDELIVERABLE") {
                result.score += 5;
                result.flags.push(`Email address is undeliverable (${apiResult.email_deliverability.status_detail}) — sender may be spoofed or fake`);
            }
            if (apiResult.email_quality?.is_disposable) {
                result.score += 5;
                result.flags.push("Disposable/temporary email address detected — commonly used to avoid identification in phishing");
            }
            if (!apiResult.email_deliverability?.is_mx_valid) {
                result.score += 4;
                result.flags.push("No mail server found for this domain — domain may be fake or newly created for phishing");
            }
            if (apiResult.email_domain?.is_risky_tld) {
                result.score += 2;
                result.flags.push("Domain uses a high-risk top-level domain — commonly associated with phishing");
            }
            if (apiResult.email_domain?.domain_age !== null && apiResult.email_domain?.domain_age < 30) {
                result.domainAge = apiResult.email_domain.domain_age;
                result.score += 3;
                result.flags.push(`Domain is only ${apiResult.email_domain.domain_age} days old — newly registered domains are a common phishing tactic`);
            }
            if (apiResult.email_risk?.address_risk_status === "high") {
                result.score += 5;
                result.flags.push("Email address flagged as high risk by reputation database");
            } else if (apiResult.email_risk?.domain_risk_status === "high") {
                result.score += 4;
                result.flags.push("Email domain flagged as high risk by reputation database");
            }
            if (apiResult.email_quality?.is_username_suspicious) {
                result.score += 2;
                result.flags.push("Username appears auto-generated or suspicious — common in phishing and spam accounts");
            }
            if (
                apiResult.email_quality?.score !== undefined &&
                apiResult.email_quality?.score !== null &&
                apiResult.email_quality.score < 0.5 &&
                apiResult.email_deliverability?.status !== "UNDELIVERABLE"
            ) {
                result.score += 3;
                result.flags.push(`Low email quality score (${apiResult.email_quality.score}) — address may be suspicious despite being deliverable`);
            }
            if (result.flags.length === 0) {
                result.flags.push("Email address appears valid and low risk — verify the sender's identity manually");
            }
        } else {
            result.source = "Pattern Fallback";
            result.flags.push("Email validation API unavailable — using pattern-based analysis");
            runSenderPatterns(sender, result);
        }
    } else if (senderType === "phone") {
        if (!sender.trim().startsWith("+")) {
            result.flags.push("Tip: Include your country code for accurate validation (e.g. +1 for US). Without it, the country may be misidentified.");
        }
        const apiResult = await checkNumVerify(sender);
        if (apiResult) {
            result.maxScore = 20;
            if (apiResult.valid === false) {
                result.score += 15;
                result.flags.push("Invalid phone number format — high risk of being a spoofed or fake identity");
            } else {
                if (apiResult.line_type === "voip") {
                    result.score += 12;
                    result.flags.push("Virtual/VOIP number detected — often used by scammers to hide their true location");
                }
                if (apiResult.country_code && apiResult.country_code !== "US") {
                    result.score += 3;
                    result.flags.push(`International number detected (${apiResult.country_name}) — verify if you expect calls from this region`);
                }
                if (apiResult.carrier) {
                    result.flags.push(`Verified ${apiResult.line_type} line with ${apiResult.carrier}`);
                } else {
                    result.flags.push("Phone number appears valid — verify the sender's identity manually");
                }
            }
        } else {
            result.flags.push("Phone validation API unavailable — verify this number manually");
            runSenderPatterns(sender, result);
        }
    } else {
        result.flags.push("Unrecognized sender format — could not determine if this is an email or phone number");
        runSenderPatterns(sender, result);
    }

    result.score = Math.min(result.score, result.maxScore);
    return result;
}

async function patternLinks(input) {
    const result = { score: 0, maxScore: 20, flags: [], links: [] };
    const links  = input?.split("\n").map(l => l.trim()).filter(l => l.length > 0) ?? [];

    if (links.length === 0) {
        result.maxScore = 10;
        result.flags.push("No link(s) provided — if the email contains links, consider adding them for analysis");
        return result;
    }

    let apiFlaggedUrls = [];
    let apiUsed = null;

    // 1. Try VirusTotal Primary
    const vtMatches = await checkVirusTotal(links);
    if (vtMatches !== null) {
        apiUsed = "VirusTotal";
        apiFlaggedUrls = vtMatches;
    } else {
        // 2. Fallback to GSB Backup
        const gsbMatches = await checkGoogleSafeBrowsing(links);
        if (gsbMatches !== null) {
            apiUsed = "Google Safe Browsing";
            apiFlaggedUrls = gsbMatches;
        }
    }

    // 3. Process API Results if an API succeeded
    if (apiUsed !== null) {
        result.source = `API (${apiUsed})`;
        
        if (apiFlaggedUrls.length > 0) {
            result.score += 20;
            apiFlaggedUrls.forEach(match => {
                const linkUrl = apiUsed === "VirusTotal" ? match.url : match.threat.url;
                const flagMsg = apiUsed === "VirusTotal" 
                    ? `Flagged by ${match.malicious} ${match.malicious === 1 ? 'vendor' : 'vendors'} as malicious on VirusTotal`
                    : `Flagged by Google Safe Browsing as ${match.threatType.replace(/_/g, " ").toLowerCase()}`;
                
                result.flags.push(`Confirmed malicious URL detected by ${apiUsed} — verify links manually before clicking`);
                result.links.push({
                    link: linkUrl,
                    linkScore: 20,
                    linkFlags: [flagMsg],
                });
            });
        }
        
        const flaggedSet = new Set(apiFlaggedUrls.map(m => apiUsed === "VirusTotal" ? m.url : m.threat.url));
        
        // Continue checking API-approved links for suspicious visual patterns (shorteners, IP addresses, etc.)
        links.forEach(link => {
            if (flaggedSet.has(link)) return;
            let ls = 0; let lf = [];
            const ipMatch = link.match(/https?:\/\/(\d{1,3}\.){3}\d{1,3}/);
            if (ipMatch) { ls += 2; lf.push(`IP address used instead of domain — "${ipMatch[0]}"`); }
            const shortenerMatch = link.match(/https?:\/\/(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|rb\.gy|shorturl\.at)/i);
            if (shortenerMatch) { ls += 2; lf.push(`URL shortener detected — "${shortenerMatch[1]}" hides the real destination`); }
            const brandMatch = link.match(/payp[a@4]l|g[o0]{2}gle|micr[o0]s[o0]ft|[a@]pp?le|amaz[o0]n|netfl[i1]x/i);
            const isLegitBrandDomain = /^https?:\/\/(www\.)?(paypal\.com|google\.com|microsoft\.com|apple\.com|amazon\.com|netflix\.com)(\/|$)/i.test(link);
            if (brandMatch && !isLegitBrandDomain) {
                ls += 5;
                lf.push(`Possible brand spoofing in URL — "${brandMatch[0]}" detected`);
            }
            if (ls > 0) {
                result.score += ls;
                result.links.push({ link, linkScore: ls, linkFlags: lf });
                lf.forEach(f => result.flags.push(f));
            }
        });
        
        if (result.flags.length === 0) {
            result.flags.push(`No threats detected by ${apiUsed} — verify links manually before clicking`);
        }
    } else {
        // 4. Ultimate Fallback to Pattern-Only Analysis
        result.source = "Pattern Fallback";
        result.maxScore = 10;
        let worstScore = 0;
        let worstFlags = [];

        links.forEach(link => {
            let ls = 0; let lf = [];
            const ipMatch = link.match(/https?:\/\/(\d{1,3}\.){3}\d{1,3}/);
            if (ipMatch) { ls += 4; lf.push(`IP address used instead of domain — "${ipMatch[0]}"`); }
            const shortenerMatch = link.match(/https?:\/\/(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|rb\.gy|shorturl\.at)/i);
            if (shortenerMatch) { ls += 3; lf.push(`URL shortener detected — "${shortenerMatch[1]}" hides the real destination`); }
            const misleadingMatch = link.match(/https?:\/\/([\w-]+\.)+([\w-]+\.)(com|org|net|gov)\.([\w-]+\.)+/i);
            if (misleadingMatch) { ls += 3; lf.push("Misleading subdomain detected — real domain may be hidden in the URL"); }
            const tldMatch = link.match(/\.(xyz|top|click|loan|work|gq|ml|cf|tk|zip|mov)$/i);
            if (tldMatch) { ls += 2; lf.push(`Unusual domain extension "${tldMatch[1]}" — commonly used in phishing links`); }
            const hyphenMatch = link.match(/[-]{2,}|([a-z]+-){3,}/i);
            if (hyphenMatch) { ls += 1; lf.push("Excessive hyphens in URL — common in spoofed links"); }
            const brandMatch = link.match(/payp[a@4]l|g[o0]{2}gle|micr[o0]s[o0]ft|[a@]pp?le|amaz[o0]n|netfl[i1]x/i);
            const isLegitBrandDomain = /^https?:\/\/(www\.)?(paypal\.com|google\.com|microsoft\.com|apple\.com|amazon\.com|netflix\.com)(\/|$)/i.test(link);
            if (brandMatch && !isLegitBrandDomain) { ls += 3; lf.push(`Possible brand spoofing in URL — "${brandMatch[0]}" detected`); }
            
            ls = Math.min(ls, result.maxScore);
            if (ls > worstScore) { worstScore = ls; worstFlags = lf; }
            result.links.push({ link, linkScore: ls, linkFlags: lf });
        });

        result.score = worstScore;
        result.flags = [...result.flags, ...worstFlags];
        if (worstFlags.length === 0) result.flags.push("No obvious patterns detected — verify links manually before clicking");
    }

    result.score = Math.min(result.score, result.maxScore);
    return result;
}

function patternSubject(subject) {
    const result = { score: 0, maxScore: 15, flags: [], display: subject };

    if (!subject || subject.trim() === "") {
        result.flags.push("No subject provided — if the email has a subject line, consider adding it for analysis");
        return result;
    }

    const capsMatch = subject.match(/\b[A-Z]{3,}\b/g);
    if (capsMatch) { result.score += 2; result.flags.push(`All-caps words detected — "${capsMatch[0]}" — commonly used to create urgency`); }

    const urgencyMatch = subject.match(/\b(urgent|immediate|act now|expires|deadline|last chance|final notice|response required|time sensitive)\b/i);
    if (urgencyMatch) { result.score += 3; result.flags.push(`Urgency language detected — "${urgencyMatch[0]}" — pressures recipients into acting without thinking`); }

    const threatMatch = subject.match(/\b(suspended|locked|unauthorized|compromised|blocked|disabled|deactivated|restricted|unusual activity|suspicious activity)\b/i);
    if (threatMatch) { result.score += 3; result.flags.push(`Threatening language detected — "${threatMatch[0]}" — used to create fear and prompt immediate action`); }

    const prizeMatch = subject.match(/\b(winner|won|congratulations|you have been selected|claim your|free|reward|prize|gift card|lucky)\b/i);
    if (prizeMatch) { result.score += 3; result.flags.push(`Reward bait detected — "${prizeMatch[0]}" — common in phishing and scam emails`); }

    const actionMatch = subject.match(/\b(verify your|confirm your|update your|validate your|sign in|log in|click here|open immediately)\b/i);
    if (actionMatch) { result.score += 2; result.flags.push(`Action request detected — "${actionMatch[0]}" — phishing emails commonly push recipients to take immediate action`); }

    const punctMatch = subject.match(/[!?]{2,}/);
    if (punctMatch) { result.score += 1; result.flags.push(`Excessive punctuation detected — "${punctMatch[0]}" — used to amplify urgency`); }

    const dollarMatch = subject.match(/\$[\d,]+/);
    if (dollarMatch) { result.score += 1; result.flags.push(`Dollar amount detected — "${dollarMatch[0]}" — commonly used as bait in phishing emails`); }

    if (result.flags.length === 0) result.flags.push("No suspicious patterns detected in subject line — this does not mean the email is safe");

    result.score = Math.min(result.score, result.maxScore);
    return result;
}

function patternSusTexts(body) {
    const result = { score: 0, maxScore: 15, flags: [], display: body };

    if (!body || body.trim() === "") {
        result.flags.push("No body text provided — if the email has a body, consider adding it for analysis");
        return result;
    }

    const credentialMatch = body.match(/\b(enter your password|confirm your (password|credentials)|verify your (account|identity|email)|your (username|password|login))\b/gi);
    if (credentialMatch) { result.score += 4; result.flags.push(`Credential request detected ${credentialMatch.length > 1 ? `(${credentialMatch.length} times)` : ""} — "${credentialMatch[0]}" — legitimate organizations rarely ask for credentials via email`); }

    const personalMatch = body.match(/\b(social security|credit card|bank account|date of birth|billing information|card number|cvv|routing number)\b/gi);
    if (personalMatch) { result.score += 4; result.flags.push(`Personal information request detected ${personalMatch.length > 1 ? `(${personalMatch.length} times)` : ""} — "${personalMatch[0]}" — never provide sensitive information via email`); }

    const urgentActionMatch = body.match(/\b(click the link below|click here immediately|download the attachment|open the attached|act immediately|respond immediately)\b/gi);
    if (urgentActionMatch) { result.score += 3; result.flags.push(`Urgent action phrase detected ${urgentActionMatch.length > 1 ? `(${urgentActionMatch.length} times)` : ""} — "${urgentActionMatch[0]}" — used to pressure recipients into acting without thinking`); }

    const impersonationMatch = body.match(/\b(we have noticed|we detected|we have detected|our records indicate|our system|we are contacting you|this is an automated)\b/gi);
    if (impersonationMatch) { result.score += 2; result.flags.push(`Impersonation language detected ${impersonationMatch.length > 1 ? `(${impersonationMatch.length} times)` : ""} — "${impersonationMatch[0]}" — commonly used to appear as a legitimate organization`); }

    const greetingMatch = body.match(/\b(dear customer|dear user|dear account holder|dear member|dear valued customer|hello user)\b/gi);
    if (greetingMatch) { result.score += 1; result.flags.push(`Generic greeting detected — "${greetingMatch[0]}" — legitimate organizations typically address you by name`); }

    const threatMatch = body.match(/\b(your account will be (closed|suspended|terminated|deactivated)|failure to (comply|respond|verify)|you will lose access|access will be (revoked|terminated))\b/gi);
    if (threatMatch) { result.score += 3; result.flags.push(`Threat language detected ${threatMatch.length > 1 ? `(${threatMatch.length} times)` : ""} — "${threatMatch[0]}" — used to create fear and prompt immediate action`); }

    const linkAnchorMatch = body.match(/\b(click here|login here|verify here|access here|continue here|proceed here)\b/gi);
    if (linkAnchorMatch) { result.score += 2; result.flags.push(`Suspicious link anchor detected ${linkAnchorMatch.length > 1 ? `(${linkAnchorMatch.length} times)` : ""} — "${linkAnchorMatch[0]}" — vague link text is commonly used to hide malicious destinations`); }

    if (result.flags.length === 0) result.flags.push("No suspicious patterns detected in body text — this does not mean the email is safe");

    result.score = Math.min(result.score, result.maxScore);
    return result;
}

// ─── DISPLAY RESULTS ─────────────────────────────────────────

function setRiskMeter(riskLevel) {
    const positions = [2, 25, 50, 75, 97];
    document.getElementById("risk-needle").style.left = `${positions[riskLevel]}%`;
    document.getElementById("needle-label").textContent = RISK_LABEL[riskLevel];
}

function displayResults(senderResult, linksResult, aiResult, subjectResult, textResult, data) {
    const scoreResult = calculateScore({ senderResult, linksResult, aiResult, subjectResult, textResult, data });
    const senderRisk  = assessSender(senderResult);
    const linksRisk   = assessLinks(linksResult);
    const contentRisk = assessContent(aiResult, subjectResult, textResult, data);
    const coverage    = buildCoverageSummary(senderResult, linksResult, aiResult, subjectResult, textResult, data);

    // Sender card
    document.getElementById("sender-card").innerHTML = `
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
            <div class="indicator ${senderRisk === null ? "gray" : RISK_COLOR[senderRisk]}"></div>
            <h3>Sender Analysis</h3>
            <span class="risk-badge ${senderRisk === null ? "badge-na" : RISK_BADGE[senderRisk]}">${senderRisk === null ? "N/A" : RISK_LABEL[senderRisk]}</span>
        </div>
        <ul>${senderResult.flags.map(f => `<li>${f}</li>`).join("")}</ul>
    `;

    // Content card
    document.getElementById("content-card").innerHTML = `
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
            <div class="indicator ${contentRisk === null ? "gray" : RISK_COLOR[contentRisk]}"></div>
            <h3>Content Analysis</h3>
            <span class="risk-badge ${contentRisk === null ? "badge-na" : RISK_BADGE[contentRisk]}">${contentRisk === null ? "N/A" : RISK_LABEL[contentRisk]}</span>
        </div>
        <ul>
            ${contentRisk === null
                ? "<li>No subject or body text provided — add content for analysis</li>"
                : aiResult
                    ? aiResult.themes?.length > 0
                        ? aiResult.themes.map(t => `<li><strong>${t.theme}</strong> — ${Math.round(t.share * 100)}% of phishing signals</li>`).join("")
                        : "<li>AI model analysis complete — confidence score used in overall risk calculation</li>"
                    : [...subjectResult.flags, ...textResult.flags].map(f => `<li>${f}</li>`).join("")
            }
        </ul>
    `;

    // Links card
    document.getElementById("links-card").innerHTML = `
        <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">
            <div class="indicator ${linksRisk === null ? "gray" : RISK_COLOR[linksRisk]}"></div>
            <h3>Link(s) Analysis</h3>
            <span class="risk-badge ${linksRisk === null ? "badge-na" : RISK_BADGE[linksRisk]}">${linksRisk === null ? "N/A" : RISK_LABEL[linksRisk]}</span>
        </div>
        <ul>${linksResult.flags.map(f => `<li>${f}</li>`).join("")}</ul>
        ${linksResult.links.length > 0 ? `<h4>All Links Analyzed:</h4>${linksResult.links.map(l => `<div class="link-entry">${l.link} — ${l.linkFlags[0]}</div>`).join("")}` : ""}
    `;

    // User context
    document.getElementById("user-context-breakdown-text").innerHTML =
        scoreResult.checkedSignals.length > 0
            ? `<ul>${scoreResult.checkedSignals.map(c => `<li>${c}</li>`).join("")}</ul>`
            : `<p>No context provided — checking relevant boxes helps improve the accuracy of your assessment</p>`;

    // Coverage
    const { provided, missing } = coverage;
    document.getElementById("coverage-summary").innerHTML = `
        <p><strong>Score based on:</strong> ${provided.length > 0 ? provided.join(", ") : "Nothing provided yet"}</p>
        ${missing.length > 0 ? `<p><strong>Not analyzed:</strong></p><ul>${missing.map(m => `<li>${m}</li>`).join("")}</ul>` : "<p>All signal categories were analyzed.</p>"}
    `;

    // Summary + meter
    document.getElementById("what-this-means-text").textContent = generateSummary(scoreResult, senderRisk, linksRisk, contentRisk);
    setRiskMeter(scoreResult.overallRisk);
}

// ─── MAIN FLOW ───────────────────────────────────────────────

async function runAnalysis(data) {
    showView("view-loading");
    const msgInterval = cycleLoadingMessages();

    const senderResult  = await patternSender(data.senderChecked);
    const linksResult   = await patternLinks(data.susLinksChecked);
    const subjectResult = patternSubject(data.subjectChecked);
    const textResult    = patternSusTexts(data.susTextsChecked);
    const aiResult      = await callAIModel(data.subjectChecked, data.susTextsChecked);

    clearInterval(msgInterval);
    displayResults(senderResult, linksResult, aiResult, subjectResult, textResult, data);
    showView("view-results");
}

// ─── INIT ────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {

    // Pre-fill fields if data came from Gmail/Outlook extraction
    chrome.storage.local.get("phishlyData", (result) => {
        const d = result.phishlyData;
        if (!d) return;
        if (d.senderChecked)   document.getElementById("sender").value    = d.senderChecked;
        if (d.subjectChecked)  document.getElementById("subject").value   = d.subjectChecked;
        if (d.susTextsChecked) document.getElementById("sus_texts").value = d.susTextsChecked;
        if (d.susLinksChecked) document.getElementById("sus_links").value = d.susLinksChecked;

        document.getElementById("urgent_checkbox").checked = d.urgentChecked               ?? false;
        document.getElementById("une_send").checked        = d.unexpectedSenderChecked     ?? false;
        document.getElementById("asks_login").checked      = d.asksLoginChecked            ?? false;
        document.getElementById("sens_info").checked       = d.sensititiveInfoChecked      ?? false;
        document.getElementById("une_att").checked         = d.unexpectedAttachmentChecked ?? false;
        document.getElementById("qr_code").checked         = d.qrCodeChecked ?? false;

        // Auto-resize textareas
        ["subject", "sus_texts", "sus_links"].forEach(id => {
            const el = document.getElementById(id);
            if (el) { el.style.height = "auto"; el.style.height = el.scrollHeight + "px"; }
        });

        // Clear storage after reading so stale data doesn't persist
        chrome.storage.local.remove("phishlyData");
    });

    // Auto-resize textareas on input
    ["subject", "sus_texts", "sus_links"].forEach(id => {
        document.getElementById(id)?.addEventListener("input", function () {
            this.style.height = "auto";
            this.style.height = this.scrollHeight + "px";
        });
    });

    // Analyze button
    document.getElementById("analyze_button").addEventListener("click", () => {
        const sender  = document.getElementById("sender").value.trim();
        const subject = document.getElementById("subject").value.trim();
        const body    = document.getElementById("sus_texts").value.trim();
        const links   = document.getElementById("sus_links").value.trim();
        const anyCheckbox =
            document.getElementById("urgent_checkbox").checked ||
            document.getElementById("une_send").checked ||
            document.getElementById("asks_login").checked ||
            document.getElementById("sens_info").checked ||
            document.getElementById("une_att").checked ||
            document.getElementById("qr_code").checked;

        if (!sender && !subject && !body && !links && !anyCheckbox) {
            alert("Please provide at least one signal to analyze.");
            return;
        }

        const data = {
            senderChecked:               sender,
            subjectChecked:              subject,
            susTextsChecked:             body,
            susLinksChecked:             links,
            urgentChecked:               document.getElementById("urgent_checkbox").checked,
            unexpectedSenderChecked:     document.getElementById("une_send").checked,
            asksLoginChecked:            document.getElementById("asks_login").checked,
            sensititiveInfoChecked:      document.getElementById("sens_info").checked,
            unexpectedAttachmentChecked: document.getElementById("une_att").checked,
            qrCodeChecked:               document.getElementById("qr_code").checked,
        };

        runAnalysis(data);
    });

    // Go back button
    document.getElementById("go_back").addEventListener("click", () => {
        ["sender", "subject", "sus_texts", "sus_links"].forEach(id => {
            const el = document.getElementById(id);
            if (el) { el.value = ""; el.style.height = "auto"; }
        });
        ["urgent_checkbox", "une_send", "asks_login", "sens_info", "une_att", "qr_code"].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.checked = false;
        });
        showView("view-main");
    });
});