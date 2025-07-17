console.log("✅ Background service worker loaded");

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  console.log("🌀 Tab update detected:", tab.url, changeInfo);

  // Proceed only when tab is fully loaded
  if (changeInfo.status === "complete") {
    if (tab.url && tab.url.startsWith("http")) {
      const url = tab.url;
      const username = "eniola";

      console.log("✅ Valid URL — sending to API:", url);

      fetch("http://172.20.10.2:8000/scan_and_save", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ url, username })
      })
        .then(async res => {
          if (!res.ok) {
            const text = await res.text();
            throw new Error(`Server error: ${res.status} - ${text}`);
          }
          return res.json();
        })
        .then(data => {
          if (data.label !== undefined) {
            const isPhishing = data.label === 1;
            const message = isPhishing ? "⚠️ Phishing Site!" : "✅ Safe Site";

            chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
              if (tabs.length === 0) {
                console.warn("⚠️ No active tab found.");
                return;
              }

              try {
                chrome.tabs.sendMessage(tabs[0].id, {
                  type: "SHOW_RESULT",
                  label: message,
                  confidence: data.confidence
                });
                console.log("✅ Message sent to content script.");
              } catch (err) {
                console.warn("❌ Failed to send message to content script:", err.message);
              }
            });
          } else {
            console.error("⚠️ Unexpected API response:", data);
          }
        })
        .catch(error => {
          console.error("❌ Error calling API:", error.message);
        });
    } else {
      console.log("⛔️ Skipped non-HTTP URL:", tab.url);
    }
  }
});
