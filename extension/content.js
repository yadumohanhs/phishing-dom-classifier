(async function runPhishGuard() {
  const currentUrl = window.location.href;

  // 1. Skip scanning our own FastAPI docs or internal browser pages
  if (
    currentUrl.includes("127.0.0.1:8000") ||
    currentUrl.includes("localhost:8000")
  ) {
    return;
  }

  // 2. Grab the rendered DOM tree (HTML string)
  const pageHtml = document.documentElement.outerHTML;

  try {
    // 3. Send URL + DOM to our local FastAPI backend
    const response = await fetch("http://127.0.0.1:8000/analyze", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        url: currentUrl,
        html: pageHtml,
      }),
    });

    if (!response.ok) {
      console.warn("[PhishGuard] Backend returned status:", response.status);
      return;
    }

    const result = await response.json();
    console.log("[PhishGuard Analysis]", result);

    // 4. Render the visual alert or badge on the page
    renderSecurityUI(result);
  } catch (error) {
    console.warn(
      "[PhishGuard] Could not reach local FastAPI server at 127.0.0.1:8000. Is uvicorn running?",
      error
    );
  }
})();

function renderSecurityUI(data) {
  // Prevent duplicate banners if script runs twice
  if (document.getElementById("phishguard-overlay")) return;

  const container = document.createElement("div");
  container.id = "phishguard-overlay";

  if (data.verdict === "PHISHING" || data.verdict === "SUSPICIOUS") {
    const isPhishing = data.verdict === "PHISHING";
    const bgColor = isPhishing ? "#dc2626" : "#d97706"; // Red for Phishing, Amber for Suspicious

    // Full-width top warning banner
    container.style.cssText = `
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      background-color: ${bgColor};
      color: #ffffff;
      z-index: 2147483647;
      padding: 14px 24px;
      font-family: system-ui, -apple-system, sans-serif;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
      display: flex;
      justify-content: space-between;
      align-items: center;
      box-sizing: border-box;
    `;

    const reasonsList = data.reasons.map((r) => `• ${r}`).join(" &nbsp;|&nbsp; ");

    container.innerHTML = `
      <div>
        <div style="font-size: 16px; font-weight: 700; letter-spacing: 0.5px;">
          ⚠️ PhishGuard Alert: ${data.verdict} DETECTED (Risk Score: ${data.risk_score}%)
        </div>
        <div style="font-size: 13px; margin-top: 4px; opacity: 0.95;">
          ${reasonsList}
        </div>
      </div>
      <button id="phishguard-dismiss" style="
        background: rgba(255,255,255,0.2);
        border: 1px solid #fff;
        color: #fff;
        padding: 6px 12px;
        border-radius: 4px;
        cursor: pointer;
        font-weight: 600;
        font-size: 12px;
      ">Dismiss</button>
    `;

    document.body.prepend(container);
    document.getElementById("phishguard-dismiss").onclick = () => container.remove();

  } else {
    // Small, unobtrusive green pill in the bottom-right corner for SAFE pages
    container.style.cssText = `
      position: fixed;
      bottom: 16px;
      right: 16px;
      background-color: #059669;
      color: #ffffff;
      z-index: 2147483647;
      padding: 8px 14px;
      border-radius: 9999px;
      font-family: system-ui, -apple-system, sans-serif;
      font-size: 12px;
      font-weight: 600;
      box-shadow: 0 4px 10px rgba(0,0,0,0.2);
      cursor: pointer;
      transition: opacity 0.3s ease;
    `;
    container.innerHTML = `🛡️ PhishGuard: SAFE (${data.risk_score}% Risk)`;
    container.title = "Click to dismiss";
    container.onclick = () => container.remove();

    document.body.appendChild(container);

    // Auto-hide the green safe badge after 5 seconds so it doesn't annoy the user
    setTimeout(() => {
      if (container) container.style.opacity = "0";
      setTimeout(() => container.remove(), 300);
    }, 5000);
  }
}
