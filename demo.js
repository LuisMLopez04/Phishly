
// ── EMAIL DATA ────────────────────────────────────────────────────

const EMAILS = [
  {
    id: 0,
    unread: false,
    riskColor: 'var(--risk-clean)',
    riskClass: 'pill-clean',
    riskLabel: 'Likely Clean',
    senderName: 'Amazon',
    senderAddr: 'ship-confirm@amazon.com',
    subject: 'Your order has shipped — arriving Thursday',
    time: '10:14 AM',
    date: 'Today, 10:14 AM',
    preview: 'Hi Alex, your order of "Anker USB-C Charging Hub (7-in-1)" has shipped...',
    body: `Hi Alex,

Your order of "Anker USB-C Charging Hub (7-in-1)" has shipped and is on its way.

Estimated delivery: Thursday, April 24
Tracking number: 1Z999AA10123456784

You can track your package at any time using the link below. No action is required on your part.

Thank you for shopping with us.
— The Amazon Fulfillment Team`,
    links: 'https://www.amazon.com/progress-tracker/package/?orderId=112-3145678-9988712',
    linksDisplay: 'amazon.com/progress-tracker/...',
    phishlyData: {
      senderChecked: 'ship-confirm@amazon.com',
      subjectChecked: 'Your order has shipped — arriving Thursday',
      susTextsChecked: 'Your order of "Anker USB-C Charging Hub (7-in-1)" has shipped...',
      susLinksChecked: 'https://www.amazon.com/progress-tracker/package/?orderId=112-3145678-9988712',
      urgentChecked: false,
      unexpectedSenderChecked: false,
      asksLoginChecked: false,
      sensititiveInfoChecked: false,
      unexpectedAttachmentChecked: false,
      qrCodeChecked: false,
    },
    speakerNote: '→ LEGIT: Standard transactional email. No red flags triggered.'
  },
  {
    id: 1,
    unread: false,
    riskColor: 'var(--risk-clean)',
    riskClass: 'pill-clean',
    riskLabel: 'Likely Clean',
    senderName: 'GitHub',
    senderAddr: 'noreply@github.com',
    subject: '[GitHub] Please reset your password',
    time: '11:05 AM',
    date: 'Today, 11:05 AM',
    preview: 'We heard you lost your password. Use the link below to get back into your account...',
    body: `Hi alex-dev,

We heard you lost your GitHub password. Use the link below to get back into your account. This link will expire in 24 hours.

https://github.com/password_reset/314567899bc123

If you did not request this, you can safely ignore this email.`,
    links: 'https://github.com/password_reset/314567899bc123',
    linksDisplay: 'github.com/password_reset/...',
    phishlyData: {
      senderChecked: 'noreply@github.com',
      subjectChecked: '[GitHub] Please reset your password',
      susTextsChecked: 'GitHub password reset request... link expires in 24 hours.',
      susLinksChecked: 'https://github.com/password_reset/314567899bc123',
      urgentChecked: true, // "24 hours"
      unexpectedSenderChecked: false,
      asksLoginChecked: false,
      sensititiveInfoChecked: false,
      unexpectedAttachmentChecked: false,
      qrCodeChecked: false,
    },
    speakerNote: '→ LEGIT (URGENT): Shows that "Urgent" alone doesn\'t make an email malicious if the sender and link are verified.'
  },
  {
    id: 2,
    unread: true,
    riskColor: 'var(--risk-moderate)',
    riskClass: 'pill-moderate',
    riskLabel: 'Moderate',
    senderName: 'Daily Tech News',
    senderAddr: 'newsletter@substack.com',
    subject: 'Your Weekly AI & Tech Update!',
    time: '9:52 AM',
    date: 'Today, 9:52 AM',
    preview: 'In this week\'s issue: The future of LLMs and new hardware releases...',
    body: `Hey there,

Thanks for being a subscriber. Here are the top stories for this week.

Check out the full breakdown on our site: http://bit.ly/3xBBdeal

Cheers,
The Roundup Team`,
    links: 'http://bit.ly/3xBBdeal',
    linksDisplay: 'bit.ly/3xBBdeal (Shortened)',
    phishlyData: {
      senderChecked: 'newsletter@substack.com',
      subjectChecked: 'Your Weekly AI & Tech Update!',
      susTextsChecked: 'Weekly tech news newsletter...',
      susLinksChecked: 'http://bit.ly/3xBBdeal',
      urgentChecked: false,
      unexpectedSenderChecked: true, // Unfamiliar newsletter
      asksLoginChecked: false,
      sensititiveInfoChecked: false,
      unexpectedAttachmentChecked: false,
      qrCodeChecked: false,
    },
    speakerNote: '→ MODERATE: A "gray area" email. Shortened link + unexpected sender triggers caution but not a critical alert.'
  },
  {
    id: 3,
    unread: true,
    riskColor: 'var(--risk-high)',
    riskClass: 'pill-high',
    riskLabel: 'Suspicious',
    senderName: 'PayPal Security',
    senderAddr: 'service@paypa1-secure.com',
    subject: 'Your account has been temporarily limited',
    time: '8:33 AM',
    date: 'Today, 8:33 AM',
    preview: 'We have detected unusual activity on your PayPal account. To restore full access...',
    body: `Dear Customer,

We have detected unusual activity on your PayPal account. To restore full access, you must verify your account within 24 hours.

Please log in using the secure link below to confirm your identity.

PayPal Security Team`,
    links: 'https://paypa1-secure.com/verify-account',
    linksDisplay: 'paypa1-secure.com/verify-account',
    phishlyData: {
      senderChecked: 'service@paypa1-secure.com',
      subjectChecked: 'Your account has been temporarily limited',
      susTextsChecked: 'Unusual activity detected... verify account within 24 hours.',
      susLinksChecked: 'https://paypa1-secure.com/verify-account',
      urgentChecked: true,
      unexpectedSenderChecked: true,
      asksLoginChecked: true,
      sensititiveInfoChecked: false,
      unexpectedAttachmentChecked: false,
      qrCodeChecked: false,
    },
    speakerNote: '→ HIGH: Typo-squatting ("1" in paypa1) + Urgent + Asks Login. Multiple patterns firing.'
  },
  {
    id: 4,
    unread: true,
    riskColor: 'var(--risk-critical)',
    riskClass: 'pill-critical',
    riskLabel: 'High Risk',
    senderName: 'Wells Fargo Alerts',
    senderAddr: 'alerts@secure-wellsfarg0-login.com',
    subject: 'URGENT: Unauthorized login detected',
    time: 'Yesterday',
    date: 'Yesterday, 11:47 PM',
    preview: 'Our system has detected unauthorized access to your account from Kiev, Ukraine...',
    body: `Dear Valued Customer,

Your account will be deactivated within 2 hours unless you verify your identity.

Please enter your username, password, and Social Security number on the secure page below.

— Wells Fargo Security`,
    links: 'https://secure-wellsfarg0-login.com/verify',
    linksDisplay: 'secure-wellsfarg0-login.com/verify',
    phishlyData: {
      senderChecked: 'alerts@secure-wellsfarg0-login.com',
      subjectChecked: 'URGENT: Unauthorized login detected',
      susTextsChecked: 'Unauthorized access from Ukraine... enter SSN to verify.',
      susLinksChecked: 'https://secure-wellsfarg0-login.com/verify',
      urgentChecked: true,
      unexpectedSenderChecked: true,
      asksLoginChecked: true,
      sensititiveInfoChecked: true,
      unexpectedAttachmentChecked: false,
      qrCodeChecked: false,
    },
    speakerNote: '→ CRITICAL: The "Total Package." SSN request + Character substitution + High pressure.'
  },
  {
    id: 5,
    unread: true,
    riskColor: 'var(--risk-critical)',
    riskClass: 'pill-critical',
    riskLabel: 'Critical',
    senderName: 'Dropbox',
    senderAddr: 'no-reply@dropbox-fileshare.net',
    subject: 'Alex shared a document with you',
    time: 'Yesterday',
    date: 'Yesterday, 3:12 PM',
    preview: 'Alex Johnson has shared a file with you via Dropbox. File: "Q1 Invoice - Final.pdf"...',
    body: `Hi,

Alex Johnson has shared a file with you: "Q1 Invoice - Final.pdf"

Click the link below to view and download the file.`,
    links: 'http://testsafebrowsing.appspot.com/s/phishing.html',
    linksDisplay: 'testsafebrowsing.appspot.com/... ⚠',
    phishlyData: {
      senderChecked: 'no-reply@dropbox-fileshare.net',
      subjectChecked: 'Alex shared a document with you',
      susTextsChecked: 'Shared a file via Dropbox...',
      susLinksChecked: 'http://testsafebrowsing.appspot.com/s/phishing.html',
      urgentChecked: false,
      unexpectedSenderChecked: true,
      asksLoginChecked: false,
      sensititiveInfoChecked: false,
      unexpectedAttachmentChecked: true,
      qrCodeChecked: false,
    },
    speakerNote: '→ CRITICAL (API HIT): The email looks perfect, but the Link Analysis API (VT/GSB) found a confirmed threat.'
  },
  {
    id: 6,
    unread: true,
    riskColor: 'var(--risk-high)',
    riskClass: 'pill-high',
    riskLabel: 'Suspicious',
    senderName: '+12063941872',
    senderAddr: '+12063941872',
    subject: 'Delivery attempt failed — action required',
    time: 'Apr 22',
    date: 'Apr 22, 7:08 AM',
    preview: 'USPS NOTICE: We attempted to deliver your package today but were unable...',
    body: `USPS NOTICE: We attempted to deliver your package today but were unable to complete delivery.

To reschedule, scan the QR code attached to this message within 24 hours.`,
    links: '',
    linksDisplay: null,
    phishlyData: {
      senderChecked: '+12063941872',
      subjectChecked: 'Delivery attempt failed — action required',
      susTextsChecked: 'USPS Notice... scan QR code to reschedule.',
      susLinksChecked: '',
      urgentChecked: true,
      unexpectedSenderChecked: true,
      asksLoginChecked: false,
      sensititiveInfoChecked: true, // Payment/Address
      unexpectedAttachmentChecked: false,
      qrCodeChecked: true,
    },
    speakerNote: '→ QUISHING: Shows how Phishly catches threats hidden in QR codes where no URL is visible to standard scanners.'
  }
];

// ── STATE ────────────────────────────────────────────────────────

let selectedIndex = null;

// ── RENDER EMAIL LIST ─────────────────────────────────────────────

function renderList() {
  const container = document.getElementById('email-list-items');
  container.innerHTML = EMAILS.map((e, i) => `
    <div class="email-item ${e.unread ? 'unread' : ''} ${selectedIndex === i ? 'selected' : ''}"
         id="email-item-${i}"
         data-index="${i}">
      <div class="email-row1">
        <div class="risk-dot" style="background:${e.riskColor}"></div>
        <span class="email-sender">${e.senderName}</span>
        <span class="email-time">${e.time}</span>
      </div>
      <div class="email-subject">${e.subject}</div>
      <div class="email-preview">${e.preview}</div>
    </div>
  `).join('');
}

// ── SELECT EMAIL ──────────────────────────────────────────────────

function selectEmail(i) {
  selectedIndex = i;
  const e = EMAILS[i];

  // Mark as read
  EMAILS[i].unread = false;

  renderList();

  // Show reading pane
  document.getElementById('reading-empty').style.display = 'none';
  document.getElementById('reading-content').style.display = 'flex';

  // Fill header
  document.getElementById('r-subject').textContent = e.subject;
  document.getElementById('r-avatar').textContent = e.senderName.charAt(0).toUpperCase();
  document.getElementById('r-name').textContent = e.senderName;
  document.getElementById('r-addr').textContent = e.senderAddr;
  document.getElementById('r-date').textContent = e.date;

  const pill = document.getElementById('r-pill');
  pill.className = `risk-pill ${e.riskClass}`;
  pill.textContent = e.riskLabel;

  // Fill body
  document.getElementById('r-body').textContent = e.body;

  // Links hint
  const hint = document.getElementById('r-links-hint');
  if (e.linksDisplay) {
    hint.innerHTML = `
      <div style="font-size:11px;color:var(--muted2);margin-bottom:3px;">Linked URL detected</div>
      <span class="links-tag">
        <svg viewBox="0 0 10 10" fill="none" xmlns="http://www.w3.org/2000/svg">
          <path d="M4 6l2-2m0 0l1.5-1.5a1.5 1.5 0 012.1 2.1L8 6.1M6 4L4.5 5.5a1.5 1.5 0 01-2.1-2.1L4 2" stroke="currentColor" stroke-width="1.1" stroke-linecap="round"/>
        </svg>
        ${e.linksDisplay}
      </span>
    `;
  } else {
    hint.innerHTML = `<div style="font-size:11px;color:var(--muted2);">No links — risk driven by sender + context signals</div>`;
  }
}

// ── ANALYZE ───────────────────────────────────────────────────────

function analyzeEmail() {
  if (selectedIndex === null) return;
  const e = EMAILS[selectedIndex];

  // Attempt chrome.storage.local injection
  if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
    chrome.storage.local.set({ phishlyData: e.phishlyData }, () => {
      chrome.runtime.sendMessage({ type: "OPEN_RESULTS" });
      showToast('Data loaded — opening Phishly...');
    });
  } else {
    // Fallback: copy JSON to clipboard for manual paste
    const json = JSON.stringify(e.phishlyData, null, 2);
    navigator.clipboard.writeText(json).then(() => {
      showToast('Copied to clipboard (chrome.storage unavailable)');
    }).catch(() => {
      showToast('Open as extension page to enable auto-fill');
    });
  }
}

// ── TOAST ─────────────────────────────────────────────────────────

let toastTimeout;
function showToast(msg) {
  const toast = document.getElementById('toast');
  document.getElementById('toast-msg').textContent = msg;
  toast.classList.add('show');
  clearTimeout(toastTimeout);
  toastTimeout = setTimeout(() => toast.classList.remove('show'), 3000);
}

// ── INIT ──────────────────────────────────────────────────────────

renderList();

// Email list — event delegation
document.getElementById('email-list-items').addEventListener('click', (e) => {
  const item = e.target.closest('[data-index]');
  if (item) selectEmail(parseInt(item.dataset.index));
});

// Sidebar scenario shortcuts — event delegation
document.querySelector('.sidebar').addEventListener('click', (e) => {
  const item = e.target.closest('[data-email]');
  if (item) selectEmail(parseInt(item.dataset.email));
});

// Analyze button
document.getElementById('analyze-btn').addEventListener('click', analyzeEmail);