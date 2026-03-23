//analyze button carries data into other page

document.getElementById("analyze_button").addEventListener("click", () => {
    const data = {
        senderChecked: document.getElementById("sender").value,
        subjectChecked: document.getElementById("subject").value,
        susLinksChecked: document.getElementById("sus_links").value,
        susTextsChecked: document.getElementById("sus_texts").value,
        urgentChecked: document.getElementById("urgent_checkbox").checked,
        unexpectedSenderChecked: document.getElementById("une_send").checked,
        asksLoginChecked: document.getElementById("asks_login").checked,
        sensititiveInfoChecked: document.getElementById("sens_info").checked,
        unexpectedAttachmentChecked: document.getElementById("une_att").checked,
        qrCodeChecked: document.getElementById("qr_code").checked,
        fullBodyChecked: document.getElementById("full-body").value
    };
    localStorage.setItem("phishlyData", JSON.stringify(data));
    window.location.href = "resultpage.html"
});

document.getElementById("subject").addEventListener("input", function() {
    this.style.height = "auto";
    this.style.height = this.scrollHeight + "px";
});

document.getElementById("sus_links").addEventListener("input", function() {
    this.style.height = "auto";
    this.style.height = this.scrollHeight + "px";
});

document.getElementById("sus_texts").addEventListener("input", function() {
    this.style.height = "auto";
    this.style.height = this.scrollHeight + "px";
});