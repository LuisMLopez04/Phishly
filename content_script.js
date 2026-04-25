// content_script.js
// Injects an "Analyze with Phishly" button into open emails in Gmail and Outlook.
// When clicked, extracts sender, subject, body, and links, saves to chrome.storage.local,
// then opens the results page in a new tab.

(function () {
  "use strict";

  // ─── Detect which client we're on ────────────────────────────────────────────
  const isGmail   = window.location.hostname === "mail.google.com";
  const isOutlook = window.location.hostname.includes("outlook");

  // ─── Avoid injecting multiple buttons ────────────────────────────────────────
  const BUTTON_ID = "phishly-analyze-btn";

  function buttonAlreadyExists() {
    return !!document.getElementById(BUTTON_ID);
  }

  // ─── Create the Phishly button ────────────────────────────────────────────────
  function createButton() {
    const btn = document.createElement("button");
    btn.id = BUTTON_ID;
    btn.textContent = "Analyze with Phishly";
    btn.style.cssText = `
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 6px 14px;
      background: #e53e3e;
      color: #fff;
      border: none;
      border-radius: 4px;
      font-family: 'Space Mono', monospace, sans-serif;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 1px;
      text-transform: uppercase;
      cursor: pointer;
      margin: 8px 0;
      z-index: 9999;
      transition: background 0.15s;
    `;
    btn.addEventListener("mouseenter", () => btn.style.background = "#fc8181");
    btn.addEventListener("mouseleave", () => btn.style.background = "#e53e3e");
    return btn;
  }

  // ─── GMAIL EXTRACTION ─────────────────────────────────────────────────────────

  function extractGmail() {
    // Sender
    const senderEl = document.querySelector(".go");
    const senderEmail = document.querySelector(".gD");
    const sender = senderEmail?.getAttribute("email") || senderEl?.textContent?.trim() || "";

    // Subject
    const subjectEl = document.querySelector("h2.hP");
    const subject = subjectEl?.textContent?.trim() || "";

    // Body — grab the visible email content container
    // Gmail uses .a3s.aiL for the email body
    const bodyEl = document.querySelector(".a3s.aiL") || document.querySelector(".a3s");
    const body = bodyEl?.innerText?.trim() || "";

    // Links — collect all hrefs from the body
    const linkEls = bodyEl ? Array.from(bodyEl.querySelectorAll("a[href]")) : [];
    const links = [...new Set(
      linkEls
        .map(a => a.href)
        .filter(href => href.startsWith("http") && !href.includes("mail.google.com"))
    )].join("\n");

    return { sender, subject, body, links };
  }

  function injectGmailButton() {
     if (buttonAlreadyExists()) return;

    // .ha is the email header container that holds the subject line
    const toolbar = document.querySelector(".ha");
    if (!toolbar) return;

    const btn = createButton();
    btn.addEventListener("click", () => {
        const data = extractGmail();
        saveAndOpen(data);
    });

    // Insert after the subject heading
    const subject = toolbar.querySelector("h2.hP");
    if (subject) {
        subject.insertAdjacentElement("afterend", btn);
    } else {
        toolbar.appendChild(btn);
    }
  }

  // ─── OUTLOOK EXTRACTION ───────────────────────────────────────────────────────

  function extractOutlook() {
    // Sender — Outlook uses aria labels and specific spans
    const senderEl = document.querySelector("[aria-label='From'] span span") ||
                     document.querySelector(".OZZZK4Ih") ||
                     document.querySelector("[class*='sender']");
    const sender = senderEl?.textContent?.trim() || "";

    // Subject
    const subjectEl = document.querySelector("[aria-label='Message subject']") ||
                      document.querySelector("[class*='subject']") ||
                      document.querySelector("h1");
    const subject = subjectEl?.textContent?.trim() || "";

    // Body — Outlook renders body in a div with role="document" or specific class
    const bodyEl = document.querySelector("[role='document']") ||
                   document.querySelector("[aria-label='Message body']") ||
                   document.querySelector(".rps_4de7");
    const body = bodyEl?.innerText?.trim() || "";

    // Links
    const linkEls = bodyEl ? Array.from(bodyEl.querySelectorAll("a[href]")) : [];
    const links = [...new Set(
      linkEls
        .map(a => a.href)
        .filter(href => href.startsWith("http") && !href.includes("outlook"))
    )].join("\n");

    return { sender, subject, body, links };
  }

  function injectOutlookButton() {
    if (buttonAlreadyExists()) return;

    // Outlook toolbar — the command bar above the email reading pane
    const toolbar = document.querySelector("[role='toolbar'][aria-label='Message actions']") ||
                    document.querySelector("[class*='commandBar']") ||
                    document.querySelector("[class*='ms-CommandBar']");

    if (!toolbar) return;

    const btn = createButton();
    btn.addEventListener("click", () => {
      const data = extractOutlook();
      saveAndOpen(data);
    });

    // Insert at the beginning of the toolbar
    toolbar.insertBefore(btn, toolbar.firstChild);
  }

  // ─── SAVE + OPEN ──────────────────────────────────────────────────────────────

  function saveAndOpen(data) {
    const payload = {
      senderChecked:              data.sender,
      subjectChecked:             data.subject,
      susTextsChecked:            data.body,
      susLinksChecked:            data.links,
      urgentChecked:              false,
      unexpectedSenderChecked:    false,
      asksLoginChecked:           false,
      sensititiveInfoChecked:     false,
      unexpectedAttachmentChecked: false,
      qrCodeChecked:              false,
    };

    chrome.storage.local.set({ phishlyData: payload }, () => {
      chrome.runtime.sendMessage({ type: "OPEN_RESULTS" });
    });
  }

  // ─── OBSERVER: watch for email opens ─────────────────────────────────────────
  // Gmail and Outlook are SPAs — emails load dynamically without full page reloads.
  // We use a MutationObserver to detect when an email opens and inject the button.

  const observer = new MutationObserver(() => {
    if (buttonAlreadyExists()) return;

    if (isGmail) {
      injectGmailButton();
    } else if (isOutlook) {
      injectOutlookButton();
    }
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true,
  });

  // Also try immediately in case email is already open
  if (isGmail) {
    injectGmailButton();
  } else if (isOutlook) {
    injectOutlookButton();
  }

})();
