// ============================================================
//  PHISHLY — resultpage.js
//  New scoring engine integrated directly.
//  Sections:
//    1. Constants
//    2. Scoring engine (weights, math, risk)
//    3. API calls
//    4. Pattern analyzers
//    5. Display
//    6. Init
// ============================================================


// ─────────────────────────────────────────────────────────────
//  1. CONSTANTS
// ─────────────────────────────────────────────────────────────

const LOADING_MESSAGES = [
    "Analyzing sender...",
    "Checking links...",
    "Running AI analysis...",
    "Calculating risk score...",
];

function cycleLoadingMessages() {
    let i = 0;
    return setInterval(() => {
        const el = document.getElementById("loading-message");
        if (el) el.textContent = LOADING_MESSAGES[i % LOADING_MESSAGES.length];
        i++;
    }, 1200);
}

function showResults() {
    const overlay   = document.getElementById("loading-overlay");
    const container = document.getElementById("results-container");
    overlay.classList.add("fade-out");
    container.style.display = "block";
    setTimeout(() => overlay.remove(), 450);
}

const RISK = { CLEAN: 0, LOW: 1, MODERATE: 2, HIGH: 3, CRITICAL: 4 };
const RISK_LABEL = ["Clean", "Low", "Moderate", "High", "Critical"];
const RISK_BADGE = ["badge-clean", "badge-low", "badge-moderate", "badge-high", "badge-critical"];
const RISK_COLOR = ["green", "green", "yellow", "orange", "red"];


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

// Hard overrides: signals so definitive they bypass weighted math
const HARD_OVERRIDES = [
  {
    id: "confirmed_malicious_link",
    condition: (ctx) => ctx.googleSafeBrowsingHit === true,
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
    maximumRisk: RISK.HIGH,
  },
  {
    id: "checkboxes_only",
    condition: (ctx) => ctx.senderSource === undefined && 
                        ctx.googleSafeBrowsingHit === undefined && 
                        ctx.senderSeverity === undefined,
    maximumRisk: RISK.MODERATE,
  },
];


// ─────────────────────────────────────────────────────────────
//  2. SCORING ENGINE
// ─────────────────────────────────────────────────────────────

// --- Severity extractors: normalize raw scores to 0.0–1.0 ---

function senderSeverity(senderResult) {
  if (!senderResult?.display || senderResult.display.trim() === "") return null;
  return Math.min(senderResult.score / senderResult.maxScore, 1.0);
}

function linksSeverity(linksResult) {
  if (!linksResult || (linksResult.links.length === 0 && linksResult.score === 0)) return null;
  return Math.min(linksResult.score / linksResult.maxScore, 1.0);
}

function contentSeverity(aiResult, subjectResult, textResult, data) {
  const hasSubject = data.subjectChecked && data.subjectChecked.trim() !== "";
  const hasBody    = data.susTextsChecked && data.susTextsChecked.trim() !== "";
  if (!hasSubject && !hasBody) return null;
  if (aiResult?.probability !== undefined) return aiResult.probability;
  const patternScore = (subjectResult?.score ?? 0) + (textResult?.score ?? 0);
  return Math.min(patternScore / 30, 1.0);
}

// --- Compounding: multiple moderate signals escalate correctly ---
// Formula: 1 - (1-a)(1-b)(1-c)
// Unlike Math.max(), this raises the score when several signals fire together.

function compoundEvidence(evidenceValues) {
  if (evidenceValues.length === 0) return 0;
  return 1 - evidenceValues.reduce((product, e) => product * (1 - Math.max(0, Math.min(1, e))), 1);
}

// --- Weighted average: reliable signals carry more influence ---

function weightedAverage(contributions) {
  const totalWeight = contributions.reduce((sum, c) => sum + c.weight, 0);
  if (totalWeight === 0) return 0;
  return contributions.reduce((sum, c) => sum + c.effectiveEvidence * c.weight, 0) / totalWeight;
}

// --- Evidence → Risk enum ---

function evidenceToRisk(score) {
  if (score < 0.15) return RISK.CLEAN;
  if (score < 0.35) return RISK.LOW;
  if (score < 0.60) return RISK.MODERATE;
  if (score < 0.80) return RISK.HIGH;
  return RISK.CRITICAL;
}

// --- Build checkbox contributions ---

function buildCheckboxContributions(data) {
  const contributions    = [];
  const checkedSignals   = [];
  const highImpactSignals = [];

  if (data.unexpectedSenderChecked) {
    contributions.push({ effectiveEvidence: 1.0, weight: SIGNAL_WEIGHTS.checkbox_unexpected_sender.weight });
    checkedSignals.push("Unexpected sender");
    highImpactSignals.push("you didn't expect this message");
  }
  if (data.asksLoginChecked) {
    contributions.push({ effectiveEvidence: 1.0, weight: SIGNAL_WEIGHTS.checkbox_asks_login.weight });
    checkedSignals.push("Asks to login");
    highImpactSignals.push("a request for your credentials");
  }
  if (data.unexpectedAttachmentChecked) {
    contributions.push({ effectiveEvidence: 1.0, weight: SIGNAL_WEIGHTS.checkbox_unexpected_attachment.weight });
    checkedSignals.push("Unexpected attachment");
    highImpactSignals.push("an unverified attachment");
  }
  if (data.sensititiveInfoChecked) {
    contributions.push({ effectiveEvidence: 1.0, weight: SIGNAL_WEIGHTS.checkbox_sensitive_info.weight });
    checkedSignals.push("Sensitive info requested");
    highImpactSignals.push("a request for sensitive data");
  }
  if (data.urgentChecked) {
    contributions.push({ effectiveEvidence: 1.0, weight: SIGNAL_WEIGHTS.checkbox_urgent_language.weight });
    checkedSignals.push("Urgent language");
  }
  if (data.qrCodeChecked) {
    contributions.push({ effectiveEvidence: 1.0, weight: SIGNAL_WEIGHTS.checkbox_qr_code.weight });
    checkedSignals.push("QR code present");
    highImpactSignals.push("a suspicious QR code");
  }

  return { contributions, checkedSignals, highImpactSignals };
}

// --- Main scoring function ---
// Returns: { overallRisk, score, presentSignals, totalSignals,
//            checkedSignals, highImpactSignals, appliedOverrides }

function calculateScore({ senderResult, linksResult, aiResult, subjectResult, textResult, data }) {
  const contributions = [];
  const signalContext = {};
  let presentSignals  = 0;
  const totalSignals  = 4;

  // Sender
  const senderSev = senderSeverity(senderResult);
  if (senderSev !== null) {
    presentSignals++;
    const isApi      = senderResult.source === "API";
    const confidence = isApi ? 0.90 : 0.55;
    const weight     = isApi ? SIGNAL_WEIGHTS.sender_api.weight : SIGNAL_WEIGHTS.sender_pattern.weight;
    contributions.push({ effectiveEvidence: senderSev * confidence, weight });
    signalContext.senderSource   = senderResult.source;
    signalContext.senderSeverity = senderSev;
    signalContext.disposableEmail = senderResult.flags?.some(f => f.toLowerCase().includes("disposable")) ?? false;
    signalContext.domainAgeDays   = senderResult.domainAge ?? null;
  }

  // Links
  const linksSev = linksSeverity(linksResult);
  if (linksSev !== null) {
    presentSignals++;
    const isApi      = linksResult.source === "API";
    const confidence = isApi ? 0.95 : 0.60;
    const weight     = isApi ? SIGNAL_WEIGHTS.links_gsb.weight : SIGNAL_WEIGHTS.links_pattern.weight;
    contributions.push({ effectiveEvidence: linksSev * confidence, weight });
    signalContext.googleSafeBrowsingHit = linksResult.links?.some(l =>
      l.linkFlags?.some(f => f.toLowerCase().includes("google safe browsing"))
    ) ?? false;
  }

  // Content
  const contentSev = contentSeverity(aiResult, subjectResult, textResult, data);
  if (contentSev !== null) {
    presentSignals++;
    const isAi      = aiResult !== null && aiResult !== undefined;
    const confidence = isAi ? 0.75 : 0.45;
    const weight     = isAi ? SIGNAL_WEIGHTS.content_ai.weight : SIGNAL_WEIGHTS.content_pattern.weight;
    contributions.push({ effectiveEvidence: contentSev * confidence, weight });
  }

  // Checkboxes
  const { contributions: cbContribs, checkedSignals, highImpactSignals } = buildCheckboxContributions(data);
  if (cbContribs.length > 0) {
    presentSignals++;
    const cbEvidence   = compoundEvidence(cbContribs.map(c => c.effectiveEvidence));
    const avgCbWeight  = cbContribs.reduce((sum, c) => sum + c.weight, 0) / cbContribs.length;
    contributions.push({ effectiveEvidence: cbEvidence, weight: avgCbWeight });
  }

  // Blend compounding + weighted average
  const compoundedScore = compoundEvidence(contributions.map(c => c.effectiveEvidence));
  const weightedScore   = weightedAverage(contributions);
  const blendedScore    = (compoundedScore * 0.55) + (weightedScore * 0.45);

  // Apply hard overrides
  let overallRisk       = evidenceToRisk(blendedScore);
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

// --- Individual card risk assessors (unchanged interface, new math) ---

function assessSender(senderResult) {
  if (!senderResult?.display || senderResult.display.trim() === "") return null;
  return evidenceToRisk(senderSeverity(senderResult));
}

function assessLinks(linksResult) {
  if (!linksResult) return null;
  if (linksResult.links.length === 0 && linksResult.score === 0) return RISK.CLEAN;
  const hasCritical = linksResult.links?.some(l => l.linkFlags?.some(f => f.toLowerCase().includes("google safe browsing")));
  if (hasCritical) return RISK.CRITICAL;
  return evidenceToRisk(linksSeverity(linksResult));
}

function assessContent(aiResult, subjectResult, textResult, data) {
  const sev = contentSeverity(aiResult, subjectResult, textResult, data);
  if (sev === null) return null;
  return evidenceToRisk(sev);
}

// --- Coverage summary: tells users what was / wasn't analyzed ---

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

// --- Summary generator ---

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
    if (techNarrative) {
        s += `We detected ${techNarrative}, which is a pattern commonly seen in phishing. `;
    }
    if (humanNarrative) {
        s += techNarrative
            ? `You also indicated this email contained ${humanNarrative}. `
            : `You indicated this email contained ${humanNarrative}. `;
    }
    s += "We recommend verifying this message directly with the organization before taking any action.";
    return s;
  }
  // HIGH or CRITICAL
  let s = "This email has several characteristics commonly associated with phishing. ";
  if (techNarrative) s += `Our analysis detected ${techNarrative}. `;
  if (humanNarrative) s += `Crucially, your observation of ${humanNarrative} confirms this is a high-risk situation. `;
  if (appliedOverrides.includes("confirmed_malicious_link")) {
    s += "A link in this message was confirmed malicious by Google's database — do not click anything. ";
  }
  s += "We strongly recommend not interacting with this message.";
  return s;
}


// ─────────────────────────────────────────────────────────────
//  3. API CALLS
// ─────────────────────────────────────────────────────────────

async function checkAbstractEmail(email) {
  try {
    const response = await fetch("http://127.0.0.1:5001/verify-email", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    return await response.json();
  } catch (error) {
    console.error("Email API error:", error);
    return null;
  }
}

async function checkNumVerify(number) {
  const url = `https://apilayer.net/api/validate?access_key=${config.numVerifyKey}&number=${number}`;
  try {
    const response = await fetch(url);
    return await response.json();
  } catch (error) {
    console.error("NumVerify API error:", error);
    return null;
  }
}

async function checkGoogleSafeBrowsing(links) {
  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${config.googleSafeBrowsingKey}`;
  const requestBody = {
    client: { clientId: "phishly", clientVersion: "1.0.0" },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: links.map(link => ({ url: link })),
    },
  };
  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(requestBody),
    });
    const data = await response.json();
    return data.matches?.length > 0 ? data.matches : [];
  } catch (error) {
    console.error("Google Safe Browsing API error:", error);
    return null;
  }
}

async function callAIModel(subject, body) {
  console.log("Calling AI Model with:", { subject, body });
  try {
    const response = await fetch("http://127.0.0.1:5001/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ subject, body }),
    });
    console.log("📡 Response status:", response.status);
    const data = await response.json();
    console.log("✅ AI response received:", data);
    return data;
  } catch (error) {
    console.error("AI Server unreachable:", error);
    return null;
  }
}


// ─────────────────────────────────────────────────────────────
//  4. PATTERN ANALYZERS
// ─────────────────────────────────────────────────────────────

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
  const brandMatch = sender.match(/payp[a@4][l1]|g[o0]{2}g[l1]e|micr[o0]s[o0]ft|[a@]pp?[l1]e|amaz[o0]n|netfl[i1]x/i);
  if (brandMatch) {
    result.score += 3;
    result.flags.push(`Possible brand spoofing detected — "${brandMatch[0]}" found in address`);
  }
  const charMatch = sender.match(/[0@](?=.*@)/);
  if (charMatch && !brandMatch) {
    result.score += 1;
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
        result.domainAge = apiResult.email_domain.domain_age; // stored for hard override check
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
      if (result.flags.length === 0) {
        result.flags.push("Email address appears valid and low risk — verify the sender's identity manually");
      }
      if (
        apiResult.email_quality?.score !== undefined &&
        apiResult.email_quality?.score !== null &&
        apiResult.email_quality.score < 0.5 &&
        apiResult.email_deliverability?.status !== "UNDELIVERABLE" // 
      ) {
        result.score += 3;
        result.flags.push(`Low email quality score (${apiResult.email_quality.score}) — address may be suspicious despite being deliverable`);
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

  const links = input?.split("\n").map(l => l.trim()).filter(l => l.length > 0) ?? [];

  if (links.length === 0) {
    result.maxScore = 10;
    result.flags.push("No link(s) provided — if the email contains links, consider adding them for analysis");
    return result;
  }

  const flaggedUrls = await checkGoogleSafeBrowsing(links);

  if (flaggedUrls) {
    result.source = "API";
    if (flaggedUrls.length > 0) {
      result.score += 20;
      flaggedUrls.forEach(match => {
        result.flags.push("Confirmed malicious URL detected by Google Safe Browsing — verify links manually before clicking");
        result.links.push({
          link: match.threat.url,
          linkScore: 20,
          linkFlags: [`Flagged by Google Safe Browsing as ${match.threatType.replace(/_/g, " ").toLowerCase()}`],
        });
      });
    }

    const flaggedUrlSet = new Set(flaggedUrls.map(m => m.threat.url));
    links.forEach(link => {
      if (flaggedUrlSet.has(link)) return;
      let linkScore = 0;
      let linkFlags = [];

      const ipMatch = link.match(/https?:\/\/(\d{1,3}\.){3}\d{1,3}/);
      if (ipMatch) { linkScore += 2; linkFlags.push(`IP address used instead of domain — "${ipMatch[0]}"`); }

      const shortenerMatch = link.match(/https?:\/\/(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|rb\.gy|shorturl\.at)/i);
      if (shortenerMatch) { linkScore += 2; linkFlags.push(`URL shortener detected — "${shortenerMatch[1]}" hides the real destination`); }

      const brandMatch = link.match(/payp[a@4]l|g[o0]{2}gle|micr[o0]s[o0]ft|[a@]pp?le|amaz[o0]n|netfl[i1]x/i);
      if (brandMatch) { linkScore += 5; linkFlags.push(`Possible brand spoofing in URL — "${brandMatch[0]}" detected`); }

      if (linkScore > 0) {
        result.score += linkScore;
        result.links.push({ link, linkScore, linkFlags });
        linkFlags.forEach(f => result.flags.push(f));
      }
    });

    if (result.flags.length === 0) {
      result.flags.push("No threats detected by Google Safe Browsing — verify links manually before clicking");
    }

  } else {
    result.source = "Pattern Fallback";
    result.maxScore = 10;
    let worstScore = 0;
    let worstFlags = [];

    links.forEach(link => {
      let linkScore = 0;
      let linkFlags = [];

      const ipMatch = link.match(/https?:\/\/(\d{1,3}\.){3}\d{1,3}/);
      if (ipMatch) { linkScore += 4; linkFlags.push(`IP address used instead of domain — "${ipMatch[0]}"`); }

      const shortenerMatch = link.match(/https?:\/\/(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|rb\.gy|shorturl\.at)/i);
      if (shortenerMatch) { linkScore += 3; linkFlags.push(`URL shortener detected — "${shortenerMatch[1]}" hides the real destination`); }

      const misleadingMatch = link.match(/https?:\/\/([\w-]+\.)+([\w-]+\.)(com|org|net|gov)\.([\w-]+\.)+/i);
      if (misleadingMatch) { linkScore += 3; linkFlags.push("Misleading subdomain detected — real domain may be hidden in the URL"); }

      const tldMatch = link.match(/\.(xyz|top|click|loan|work|gq|ml|cf|tk|zip|mov)$/i);
      if (tldMatch) { linkScore += 2; linkFlags.push(`Unusual domain extension "${tldMatch[1]}" — commonly used in phishing links`); }

      const hyphenMatch = link.match(/[-]{2,}|([a-z]+-){3,}/i);
      if (hyphenMatch) { linkScore += 1; linkFlags.push("Excessive hyphens in URL — common in spoofed links"); }

      const brandMatch = link.match(/payp[a@4]l|g[o0]{2}gle|micr[o0]s[o0]ft|[a@]pp?le|amaz[o0]n|netfl[i1]x/i);
      if (brandMatch) { linkScore += 3; linkFlags.push(`Possible brand spoofing in URL — "${brandMatch[0]}" detected`); }

      linkScore = Math.min(linkScore, result.maxScore);
      if (linkScore > worstScore) { worstScore = linkScore; worstFlags = linkFlags; }
      result.links.push({ link, linkScore, linkFlags });
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


// ─────────────────────────────────────────────────────────────
//  5. DISPLAY
// ─────────────────────────────────────────────────────────────

function setRiskMeter(riskLevel) {
  const positions = [2, 25, 50, 75, 97];
  const needle    = document.getElementById("risk-needle");
  const label     = document.getElementById("needle-label");
  needle.style.left  = `${positions[riskLevel]}%`;
  label.textContent  = RISK_LABEL[riskLevel];
}

function displayResults() {
  // --- Score ---
  const scoreResult = calculateScore({ senderResult, linksResult, aiResult, subjectResult, textResult, data });
  const senderRisk  = assessSender(senderResult);
  const linksRisk   = assessLinks(linksResult);
  const contentRisk = assessContent(aiResult, subjectResult, textResult, data);
  const coverage    = buildCoverageSummary(senderResult, linksResult, aiResult, subjectResult, textResult, data);

  // --- Sender card ---
  document.getElementById("sender").innerHTML = `
    <div style="display:flex; align-items:center; gap:10px; margin-bottom:10px;">
      <div class="indicator ${senderRisk === null ? "gray" : RISK_COLOR[senderRisk]}"></div>
      <h3 style="font-family:'Space Mono',monospace;font-size:12px;font-weight:700;flex:1;margin:0;">Sender Analysis</h3>
      <span class="risk-badge ${senderRisk === null ? "badge-na" : RISK_BADGE[senderRisk]}">${senderRisk === null ? "N/A" : RISK_LABEL[senderRisk]}</span>
    </div>
    <ul>${senderResult.flags.map(f => `<li>${f}</li>`).join("")}</ul>
  `;

  // --- Links card ---
  document.getElementById("Suspicious Links").innerHTML = `
    <div style="display:flex; align-items:center; gap:10px; margin-bottom:10px;">
      <div class="indicator ${linksRisk === null ? "gray" : RISK_COLOR[linksRisk]}"></div>
      <h3 style="font-family:'Space Mono',monospace;font-size:12px;font-weight:700;flex:1;margin:0;">Link(s) Analysis</h3>
      <span class="risk-badge ${linksRisk === null ? "badge-na" : RISK_BADGE[linksRisk]}">${linksRisk === null ? "N/A" : RISK_LABEL[linksRisk]}</span>
    </div>
    <ul>${linksResult.flags.map(f => `<li>${f}</li>`).join("")}</ul>
    ${linksResult.links.length > 0 ? `
      <h4>All Links Analyzed:</h4>
      ${linksResult.links.map(l => `<div class="link-entry">${l.link} — ${l.linkFlags[0]}</div>`).join("")}
    ` : ""}
  `;

  // --- Content card ---
  document.getElementById("content-analysis").innerHTML = `
    <div style="display:flex; align-items:center; gap:10px; margin-bottom:10px;">
      <div class="indicator ${contentRisk === null ? "gray" : RISK_COLOR[contentRisk]}"></div>
      <h3 style="font-family:'Space Mono',monospace;font-size:12px;font-weight:700;flex:1;margin:0;">Content Analysis</h3>
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

  // --- User context card ---
  document.getElementById("user-context-breakdown-text").innerHTML =
    scoreResult.checkedSignals.length > 0
      ? `<ul>${scoreResult.checkedSignals.map(c => `<li>${c}</li>`).join("")}</ul>`
      : `<p>No context provided — checking relevant boxes helps improve the accuracy of your assessment</p>`;

  // --- Coverage card ---
  const coverageCard = document.getElementById("coverage-summary");
  if (coverageCard) {
    const { provided, missing } = coverage;
    coverageCard.innerHTML = `
      <p><strong>Score based on:</strong> ${provided.length > 0 ? provided.join(", ") : "Nothing provided yet"}</p>
      ${missing.length > 0
        ? `<p><strong>Not analyzed:</strong></p><ul>${missing.map(m => `<li>${m}</li>`).join("")}</ul>`
        : "<p>All signal categories were analyzed.</p>"
      }
    `;
  }

  // --- Summary and meter ---
  document.getElementById("what-this-means-text").textContent =
    generateSummary(scoreResult, senderRisk, linksRisk, contentRisk);

  setRiskMeter(scoreResult.overallRisk);
  showResults();
}



// ─────────────────────────────────────────────────────────────
//  6. INIT
// ─────────────────────────────────────────────────────────────



let data = {};
let senderResult, linksResult, subjectResult, textResult, aiResult;

async function init() {
  console.log("🟢 init() started");
  const msgInterval = cycleLoadingMessages();

  senderResult  = await patternSender(data.senderChecked);
  linksResult   = await patternLinks(data.susLinksChecked);
  subjectResult = patternSubject(data.subjectChecked);
  textResult    = patternSusTexts(data.susTextsChecked);
  aiResult      = await callAIModel(data.subjectChecked, data.susTextsChecked);

  clearInterval(msgInterval);
  displayResults();
}

// Read from chrome.storage if available, fall back to sessionStorage
if (typeof chrome !== "undefined" && chrome.storage) {
  chrome.storage.local.get("phishlyData", (result) => {
    data = result.phishlyData || {};
    init();
  });
} else {
  const raw = sessionStorage.getItem("phishlyData");
  data = raw ? JSON.parse(raw) : {};
  init();
}

document.getElementById("go_back").addEventListener("click", () => {
  window.history.back();
});