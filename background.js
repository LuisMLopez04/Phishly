// background.js
// Opens the results page in a new tab when triggered by the content script.

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "OPEN_RESULTS") {
    chrome.action.openPopup().catch(err => {
      console.error("Popup failed:", err);
    });
    sendResponse({ success: true });
  }
});
