//get data from mainpage
const data = JSON.parse(localStorage.getItem("phishlyData"));
localStorage.removeItem("phishlyData");
//run analysis
const senderResult = patternSender(data.senderChecked);
const linksResult = patternLinks(data.susLinksChecked);
const subjectResult = patternSubject(data.subjectChecked);
const textResult = patternSusTexts(data.susTextsChecked);
const checkboxResult = analyzeCheckboxes(data);


/*
Automated Signals - 70 points max
- Sender Check: 20 pts (email: Abstract API, phone: NumVerify) / 10 pts fallback (pattern-based) if APIs unavailable
- Link Check: 20 pts (Google Safe Browsing + VirusTotal) / 10 pts fallback (pattern-based) if APIs unavailable
- Subject Line Patterns: 15 pts (pattern-based now / AI model planned)
- Body Text Patterns: 15 pts (pattern-based now / AI model planned)

User Context Checkboxes - 30 points max
- Unexpected Sender: 8 pts
- Asks to login: 7 pts
- Unexpected attachment: 6 pts
- Sensitive info request: 5 pts
- Urgent language: 2 pts
- QR Code: 2 pts

Scoring:
- Normalize to 100 based on fields provided
- Let users know what fields were factored and what is missing
*/

function patternSender(sender) {
    const result = {
        score: 0,
        maxScore: 20,
        flags: [],
        display: sender
    }
     /*
        Manual pattern based analyzing
     */
    let virusTotalChecked = false; //will implement api call status in the future
    if (virusTotalChecked) {
        //implement VT api calls
    } else if (!virusTotalChecked) {
        result.maxScore = 10;
        if (!sender || sender.trim() === "") {
            result.flags.push("No sender text provided — if the email has a sender, consider adding it for analysis");
            return result;
        }
        //tld domain suspicious check
        const tldMatch = sender.match(/\.(xyz|top|click|loan|work|gq|ml|cf|tk|zip|move)$/i);
        if (tldMatch) {
            result.score += 3;
            result.flags.push(`Unusual domain extensions "${tldMatch[1]}" that is commonly used in phishing`)
        }
        //popular brand spoofing
        const brandMatch = sender.match(/payp[a@4][l1]|g[o0]{2}g[l1]e|micr[o0]s[o0]ft|[a@]pp?[l1]e|amaz[o0]n|netfl[i1]x/i);
        if (brandMatch) {
            result.score += 3;
            result.flags.push(`Possible brand spoofing detected — "${brandMatch[0]}" found in address`);
        }
        //generic character substiution -not used if brand spoofing
        const charMatch = sender.match(/[0@](?=.*@)/);
        if (charMatch && !brandMatch) { // avoid double flagging
            result.score += 1;
            result.flags.push("Possible character substitution detected in sender address");
        }
        //too many subdomains
        const domainMatch = sender.match(/@([\w.-]+)/);
        if (domainMatch && (domainMatch[1].match(/\./g) || []).length >= 3) {
            result.score += 2;
            result.flags.push(`Excessive subdomains detected — "${domainMatch[1]}"`);
        }
        // suspicious TLD
        const tldSuspicious = sender.match(/[-]{2,}|([a-z]+-){3,}/i);
        if (tldSuspicious) {
            result.score += 1;
            result.flags.push("Excessive hyphens in domain — common in spoofed addresses");
        }
        // no flags found
        if (result.flags.length === 0) {
            result.flags.push("No obvious patterns detected — verify this domain manually");
        }
    }
    result.score = Math.min(result.score, result.maxScore);
    return result;
}

function patternSusTexts(body) {
    const result = {
        score: 0,
        maxScore: 15,
        flags: [],
        display: body
    }

    if (!body || body.trim() === "") {
        result.flags.push("No body text provided — if the email has a body, consider adding it for analysis");
        return result;
    }

    // credential/login requests
    const credentialMatch = body.match(/\b(enter your password|confirm your (password|credentials)|verify your (account|identity|email)|your (username|password|login))\b/gi);
    if (credentialMatch) {
        result.score += 4;
        result.flags.push(`Credential request detected ${credentialMatch.length > 1 ? `(${credentialMatch.length} times)` : ""} — "${credentialMatch[0]}" — legitimate organizations rarely ask for credentials via email`);
    }

    // personal info requests
    const personalMatch = body.match(/\b(social security|credit card|bank account|date of birth|billing information|card number|cvv|routing number)\b/gi);
    if (personalMatch) {
        result.score += 4;
        result.flags.push(`Personal information request detected ${personalMatch.length > 1 ? `(${personalMatch.length} times)` : ""} — "${personalMatch[0]}" — never provide sensitive information via email`);
    }

    // urgent action phrases
    const urgentActionMatch = body.match(/\b(click the link below|click here immediately|download the attachment|open the attached|act immediately|respond immediately)\b/gi);
    if (urgentActionMatch) {
        result.score += 3;
        result.flags.push(`Urgent action phrase detected ${urgentActionMatch.length > 1 ? `(${urgentActionMatch.length} times)` : ""} — "${urgentActionMatch[0]}" — used to pressure recipients into acting without thinking`);
    }

    // impersonation language
    const impersonationMatch = body.match(/\b(we have noticed|we detected|we have detected|our records indicate|our system|we are contacting you|this is an automated)\b/gi);
    if (impersonationMatch) {
        result.score += 2;
        result.flags.push(`Impersonation language detected ${impersonationMatch.length > 1 ? `(${impersonationMatch.length} times)` : ""} — "${impersonationMatch[0]}" — commonly used to appear as a legitimate organization`);
    }

    // generic greetings
    const greetingMatch = body.match(/\b(dear customer|dear user|dear account holder|dear member|dear valued customer|hello user)\b/gi);
    if (greetingMatch) {
        result.score += 1;
        result.flags.push(`Generic greeting detected — "${greetingMatch[0]}" — legitimate organizations typically address you by name`);
    }

    // threat language
    const threatMatch = body.match(/\b(your account will be (closed|suspended|terminated|deactivated)|failure to (comply|respond|verify)|you will lose access|access will be (revoked|terminated))\b/gi);
    if (threatMatch) {
        result.score += 3;
        result.flags.push(`Threat language detected ${threatMatch.length > 1 ? `(${threatMatch.length} times)` : ""} — "${threatMatch[0]}" — used to create fear and prompt immediate action`);
    }

    // suspicious link anchors
    const linkAnchorMatch = body.match(/\b(click here|login here|verify here|access here|continue here|proceed here)\b/gi);
    if (linkAnchorMatch) {
        result.score += 2;
        result.flags.push(`Suspicious link anchor detected ${linkAnchorMatch.length > 1 ? `(${linkAnchorMatch.length} times)` : ""} — "${linkAnchorMatch[0]}" — vague link text is commonly used to hide malicious destinations`);
    }

    // no flags found
    if (result.flags.length === 0) {
        result.flags.push("No suspicious patterns detected in body text — this does not mean the email is safe");
    }

    result.score = Math.min(result.score, result.maxScore);
    return result;
}

function patternSubject(subject) {
    const result = {
        score: 0,
        maxScore: 15,
        flags: [],
        display: subject
    }

    if (!subject || subject.trim() === "") {
        result.flags.push("No subject provided — if the email has a subject line, consider adding it for analysis");
        return result;
    }

    // ALL CAPS words (3+ letter words in all caps)
    const capsMatch = subject.match(/\b[A-Z]{3,}\b/g);
    if (capsMatch) {
        result.score += 2;
        result.flags.push(`All-caps words detected — "${capsMatch[0]}" — commonly used to create urgency`);
    }

    // urgency keywords
    const urgencyMatch = subject.match(/\b(urgent|immediate|act now|expires|deadline|last chance|final notice|response required|time sensitive)\b/i);
    if (urgencyMatch) {
        result.score += 3;
        result.flags.push(`Urgency language detected — "${urgencyMatch[0]}" — pressures recipients into acting without thinking`);
    }

    // threat keywords
    const threatMatch = subject.match(/\b(suspended|locked|unauthorized|compromised|blocked|disabled|deactivated|restricted|unusual activity|suspicious activity)\b/i);
    if (threatMatch) {
        result.score += 3;
        result.flags.push(`Threatening language detected — "${threatMatch[0]}" — used to create fear and prompt immediate action`);
    }

    // prize/reward bait
    const prizeMatch = subject.match(/\b(winner|won|congratulations|you have been selected|claim your|free|reward|prize|gift card|lucky)\b/i);
    if (prizeMatch) {
        result.score += 3;
        result.flags.push(`Reward bait detected — "${prizeMatch[0]}" — common in phishing and scam emails`);
    }

    // request for action
    const actionMatch = subject.match(/\b(verify your|confirm your|update your|validate your|sign in|log in|click here|open immediately)\b/i);
    if (actionMatch) {
        result.score += 2;
        result.flags.push(`Action request detected — "${actionMatch[0]}" — phishing emails commonly push recipients to take immediate action`);
    }

    // excessive punctuation
    const punctMatch = subject.match(/[!?]{2,}/);
    if (punctMatch) {
        result.score += 1;
        result.flags.push(`Excessive punctuation detected — "${punctMatch[0]}" — used to amplify urgency`);
    }

    // dollar amounts
    const dollarMatch = subject.match(/\$[\d,]+/);
    if (dollarMatch) {
        result.score += 1;
        result.flags.push(`Dollar amount detected — "${dollarMatch[0]}" — commonly used as bait in phishing emails`);
    }

    // no flags found
    if (result.flags.length === 0) {
        result.flags.push("No suspicious patterns detected in subject line — this does not mean the email is safe");
    }

    result.score = Math.min(result.score, result.maxScore);
    return result;
}

function patternLinks(input) {
    const result = {
        score: 0,
        maxScore: 20,
        flags: [],
        links: []
    }

    let virusTotalChecked = false; // will implement api call status in the future
    if (virusTotalChecked) {
        // implement VT api calls
    } else {
        result.maxScore = 10;

        // split input into individual links
        const links = input.split("\n").map(l => l.trim()).filter(l => l.length > 0);

        if (links.length === 0) {
            result.flags.push("No link(s) provided — if the email contains links, consider adding them for analysis");
            return result;
        }

        let worstScore = 0;
        let worstFlags = [];

        links.forEach(link => {
            let linkScore = 0;
            let linkFlags = [];

            // IP address instead of domain
            const ipMatch = link.match(/https?:\/\/(\d{1,3}\.){3}\d{1,3}/);
            if (ipMatch) {
                linkScore += 4;
                linkFlags.push(`IP address used instead of domain — "${ipMatch[0]}"`);
            }

            // URL shorteners
            const shortenerMatch = link.match(/https?:\/\/(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|rb\.gy|shorturl\.at)/i);
            if (shortenerMatch) {
                linkScore += 3;
                linkFlags.push(`URL shortener detected — "${shortenerMatch[1]}" hides the real destination`);
            }

            // misleading subdomain (e.g. paypal.com.evil.com)
            const misleadingMatch = link.match(/https?:\/\/([\w-]+\.)+([\w-]+\.)(com|org|net|gov)\.([\w-]+\.)+/i);
            if (misleadingMatch) {
                linkScore += 3;
                linkFlags.push(`Misleading subdomain detected — real domain may be hidden in the URL`);
            }

            // suspicious TLDs
            const tldMatch = link.match(/\.(xyz|top|click|loan|work|gq|ml|cf|tk|zip|mov)$/i);
            if (tldMatch) {
                linkScore += 2;
                linkFlags.push(`Unusual domain extension "${tldMatch[1]}" — commonly used in phishing links`);
            }

            // excessive hyphens
            const hyphenMatch = link.match(/[-]{2,}|([a-z]+-){3,}/i);
            if (hyphenMatch) {
                linkScore += 1;
                linkFlags.push(`Excessive hyphens in URL — common in spoofed links`);
            }

            // brand spoofing in URL
            const brandMatch = link.match(/payp[a@4]l|g[o0]{2}gle|micr[o0]s[o0]ft|[a@]pp?le|amaz[o0]n|netfl[i1]x/i);
            if (brandMatch) {
                linkScore += 3;
                linkFlags.push(`Possible brand spoofing in URL — "${brandMatch[0]}" detected`);
            }

            // cap per link score
            linkScore = Math.min(linkScore, result.maxScore);

            // keep worst link
            if (linkScore > worstScore) {
                worstScore = linkScore;
                worstFlags = linkFlags;
            }

            // store each link result for display
            result.links.push({ link, linkScore, linkFlags });
        });

        result.score = worstScore;
        result.flags = worstFlags;

        // no flags on worst link
        if (result.flags.length === 0) {
            result.flags.push("No obvious patterns detected — verify links manually before clicking");
        }
    }

    result.score = Math.min(result.score, result.maxScore);
    return result;
}

function analyzeCheckboxes(data) {
    const result = {
        score: 0,
        maxScore: 30,
        flags: [],
        checked: []
    }

    if (data.unexpectedSenderChecked) {
        result.score += 8;
        result.checked.push("Unexpected Sender — you didn't recognize or expect this sender, which is a common indicator of phishing");
    }

    if (data.asksLoginChecked) {
        result.score += 7;
        result.checked.push("Asks to Login — legitimate organizations rarely ask you to log in via an unsolicited email");
    }

    if (data.unexpectedAttachmentChecked) {
        result.score += 6;
        result.checked.push("Unexpected Attachment — unsolicited attachments are one of the most common ways malware is delivered");
    }

    if (data.sensititiveInfoChecked) {
        result.score += 5;
        result.checked.push("Sensitive Information Requested — legitimate organizations will never ask for sensitive info via email");
    }

    if (data.urgentChecked) {
        result.score += 2;
        result.checked.push("Urgent Language — urgency is used to pressure recipients into acting without thinking");
    }

    if (data.qrCodeChecked) {
        result.score += 2;
        result.checked.push("QR Code Present — QR codes in emails can redirect to malicious sites and bypass link scanners");
    }

    // no boxes checked
    if (result.checked.length === 0) {
        result.flags.push("No context provided — checking relevant boxes helps improve the accuracy of your assessment");
    }

    result.score = Math.min(result.score, result.maxScore);
    return result;
}


function displayResults() {
    //sender
    const senderCard = document.getElementById("sender");
    senderCard.innerHTML = `
        <div style="display:flex; align-items:center; gap:8px;">
        <div class="indicator ${getIndicatorColor(senderResult.score, senderResult.maxScore)}"></div>
        <h3 style="margin:0;">Sender Analysis</h3>
        </div>
        <p>Score: ${senderResult.score} / ${senderResult.maxScore}</p>
        <ul>${senderResult.flags.map(f => `<li>${f}</li>`).join("")}</ul>
    `;

    // subject
    const subjectCard = document.getElementById("subject");
    subjectCard.innerHTML = `
        <div style="display:flex; align-items:center; gap:8px;">
        <div class="indicator ${getIndicatorColor(subjectResult.score, subjectResult.maxScore)}"></div>
        <h3 style="margin:0;">Subject Analysis</h3>
        </div>
        <p>Score: ${subjectResult.score} / ${subjectResult.maxScore}</p>
        <ul>${subjectResult.flags.map(f => `<li>${f}</li>`).join("")}</ul>
    `;

    // links
    const linksCard = document.getElementById("Suspicious Links");
    linksCard.innerHTML = `
        <div style="display:flex; align-items:center; gap:8px;">
        <div class="indicator ${getIndicatorColor(linksResult.score, linksResult.maxScore)}"></div>
        <h3 style="margin:0;">Link(s) Analysis</h3>
        </div>
        <p>Score: ${linksResult.score} / ${linksResult.maxScore}</p>
        <ul>${linksResult.flags.map(f => `<li>${f}</li>`).join("")}</ul>
        <h4>All Links Analyzed:</h4>
        ${linksResult.links.map(l => `
            <div>
                <p>${l.link} — Score: ${l.linkScore}</p>
                <ul>${l.linkFlags.map(f => `<li>${f}</li>`).join("")}</ul>
            </div>
        `).join("")}
    `;

    // sus texts
    const susTextsCard = document.getElementById("Suspicious Texts");
    susTextsCard.innerHTML = `
        <div style="display:flex; align-items:center; gap:8px;">
        <div class="indicator ${getIndicatorColor(textResult.score, textResult.maxScore)}"></div>
        <h3 style="margin:0;">Text Analysis</h3>
        </div>
        <p>Score: ${textResult.score} / ${textResult.maxScore}</p>
        <ul>${textResult.flags.map(f => `<li>${f}</li>`).join("")}</ul>
    `;

    // summary
    const contextCard = document.getElementById("user-context-breakdown-text");
    contextCard.innerHTML = checkboxResult.checked.length > 0
        ? `<ul>${checkboxResult.checked.map(c => `<li>${c}</li>`).join("")}</ul>`
        : `<p>${checkboxResult.flags[0]}</p>`;

    const summaryText = document.getElementById("what-this-means-text");
    summaryText.textContent = generateSummary(senderResult, linksResult, subjectResult, textResult, checkboxResult);

    const score = calculateRiskScore();
    setRiskMeter(score);
}

function calculateRiskScore() {
    let totalScore = 0;
    let totalMax = 0;

    if (data.senderChecked) {
        totalScore += senderResult.score;
        totalMax += senderResult.maxScore;
    }
    if (data.susLinksChecked) {
        totalScore += linksResult.score;
        totalMax += linksResult.maxScore;
    }
    if (data.subjectChecked) {
        totalScore += subjectResult.score;
        totalMax += subjectResult.maxScore;
    }
    if (data.susTextsChecked) {
        totalScore += textResult.score;
        totalMax += textResult.maxScore;
    }
    totalScore += checkboxResult.score;
    totalMax += checkboxResult.maxScore;

    // normalize to 100
    const normalized = totalMax > 0 ? Math.round((totalScore / totalMax) * 100) : 0;
    return normalized;
}

function setRiskMeter(score) {
    const needle = document.getElementById("risk-needle");
    const label = document.getElementById("needle-label");
    
    let position;
    if (score <= 25) {
        position = `${(score / 25) * 20}%`;        // 0-20% on bar (Low)
    } else if (score <= 50) {
        position = `${20 + ((score - 25) / 25) * 20}%`;  // 20-40% (Moderate)
    } else if (score <= 75) {
        position = `${40 + ((score - 50) / 25) * 20}%`;  // 40-60% (High)
    } else {
        position = `${60 + ((score - 75) / 25) * 38}%`;  // 60-98% (Critical)
    }
    
    needle.style.left = position;
    label.textContent = `${score}%`;
}

function getIndicatorColor(score, maxScore) {
    const ratio = score / maxScore;
    if (ratio <= 0.25) return "green";
    if (ratio <= 0.60) return "yellow";
    return "red";
}

function generateSummary(senderResult, linksResult, subjectResult, textResult, checkboxResult) {
    const totalScore = calculateRiskScore();
    
    // collect all triggered signals
    const highSignals = [];
    const contextSignals = [];

    if (senderResult.score > 0 && senderResult.flags[0] !== "No obvious patterns detected — verify this domain manually") {
        highSignals.push("suspicious sender");
    }
    if (linksResult.score > 0 && linksResult.flags[0] !== "No obvious patterns detected — verify links manually before clicking") {
        highSignals.push("suspicious links");
    }
    if (subjectResult.score > 0 && subjectResult.flags[0] !== "No suspicious patterns detected in subject line — this does not mean the email is safe") {
        highSignals.push("a suspicious subject line");
    }
    if (textResult.score > 0 && textResult.flags[0] !== "No suspicious patterns detected in body text — this does not mean the email is safe") {
        highSignals.push("suspicious body text");
    }
    if (checkboxResult.score > 0) {
        if (checkboxResult.checked.some(c => c.startsWith("Unexpected Sender"))) contextSignals.push("an unexpected sender");
        if (checkboxResult.checked.some(c => c.startsWith("Asks to Login"))) contextSignals.push("a login request");
        if (checkboxResult.checked.some(c => c.startsWith("Unexpected Attachment"))) contextSignals.push("an unexpected attachment");
    }

    // build summary based on score range
    let summary = "";

    if (totalScore <= 25) {
        summary = `This email shows few suspicious signals based on what you provided. `;
        if (highSignals.length > 0) {
            summary += `However, we did detect ${highSignals.join(", ")}, which is worth keeping in mind. `;
        }
        summary += `Always trust your instincts — if something feels off, verify directly with the organization through their official website.`;

    } else if (totalScore <= 50) {
        summary = `This email has some signals that are worth pausing on. `;
        if (highSignals.length > 0) {
            summary += `We detected ${highSignals.join(", ")}, which are patterns commonly seen in phishing attempts. `;
        }
        if (contextSignals.length > 0) {
            summary += `You also indicated this email contained ${contextSignals.join(", ")}. `;
        }
        summary += `We recommend verifying this message directly with the organization before taking any action.`;

    } else if (totalScore <= 75) {
        summary = `This email has several characteristics that are commonly associated with phishing. `;
        if (highSignals.length > 0) {
            summary += `We detected ${highSignals.join(", ")}, which are significant red flags. `;
        }
        if (contextSignals.length > 0) {
            summary += `Combined with ${contextSignals.join(", ")}, this email warrants serious caution. `;
        }
        summary += `Do not click any links or provide any information until you have verified this message through official channels.`;

    } else {
        summary = `This email has multiple strong indicators commonly associated with phishing attempts. `;
        if (highSignals.length > 0) {
            summary += `We detected ${highSignals.join(", ")}, which are serious red flags. `;
        }
        if (contextSignals.length > 0) {
            summary += `You also reported ${contextSignals.join(", ")}, which significantly raises concern. `;
        }
        summary += `We strongly recommend not interacting with this email. If you believe it may be legitimate, contact the organization directly through their official website — not through any information provided in this email.`;
    }

    return summary;
}

displayResults();

document.getElementById("go_back").addEventListener("click", () => {
    window.location.href = "mainpage.html"; // replace with your main page filename
});


//can implement phishtank API as a backup
