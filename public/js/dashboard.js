// public/js/dashboard.js
// Handles dashboard initialization, account display, and 2FA management.

document.addEventListener("DOMContentLoaded", async function () {
  const welcome = document.getElementById("welcome");
  const accUsername = document.getElementById("accUsername");
  const accEmail = document.getElementById("accEmail");
  const accCreated = document.getElementById("accCreated");
  const twofaStatus = document.getElementById("twofaStatus");
  const logoutBtn = document.getElementById("logoutBtn");

  const twofaOff = document.getElementById("twofaOff");
  const twofaSetupFlow = document.getElementById("twofaSetupFlow");
  const twofaOn = document.getElementById("twofaOn");
  const startSetupBtn = document.getElementById("startSetupBtn");
  const confirmSetupBtn = document.getElementById("confirmSetupBtn");
  const disableBtn = document.getElementById("disableBtn");
  const setupMsg = document.getElementById("setupMsg");
  const verifyToken = document.getElementById("verifyToken");
  const qrWrap = document.getElementById("qrWrap");
  const manualKey = document.getElementById("manualKey");

  // Fetch user data
  try {
    const response = await fetch("/api/auth/me");
    if (!response.ok) {
      window.location.href = "/index.html";
      return;
    }
    const user = await response.json();
    welcome.textContent = "Welcome back, " + user.username;
    accUsername.textContent = user.username;
    accEmail.textContent = user.email;
    accCreated.textContent = new Date(user.created_at).toLocaleDateString();

    if (user.totp_secret) {
      twofaStatus.textContent = "on";
      twofaStatus.className = "badge on";
      twofaOff.style.display = "none";
      twofaSetupFlow.style.display = "none";
      twofaOn.style.display = "block";
    }
  } catch (err) {
    console.error("Failed to fetch user data:", err);
  }

  // Start 2FA setup
  startSetupBtn.addEventListener("click", async function () {
    try {
      const response = await fetch("/api/auth/2fa/setup", { method: "POST" });
      if (!response.ok) {
        setupMsg.className = "msg error";
        setupMsg.textContent = "Failed to start 2FA setup";
        return;
      }
      const data = await response.json();
      manualKey.textContent = data.secret;
      qrWrap.innerHTML = "";
      setupMsg.className = "";
      setupMsg.textContent = "";
      verifyToken.value = "";
      twofaOff.style.display = "none";
      twofaSetupFlow.style.display = "block";

      // Generate QR code using a library
      QRCode.toSvg(data.qrCode, function (err, svg) {
        if (!err) qrWrap.appendChild(svg);
      });
    } catch (err) {
      setupMsg.className = "msg error";
      setupMsg.textContent = "Network error: " + err.message;
    }
  });

  // Confirm 2FA setup
  confirmSetupBtn.addEventListener("click", async function () {
    const token = verifyToken.value;
    if (!/^\d{6}$/.test(token)) {
      setupMsg.className = "msg error";
      setupMsg.textContent = "Enter a valid 6-digit code";
      return;
    }

    confirmSetupBtn.disabled = true;
    setupMsg.className = "msg";
    setupMsg.textContent = "Confirming...";

    try {
      const response = await fetch("/api/auth/2fa/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token }),
      });
      const data = await response.json();

      if (!response.ok) {
        setupMsg.className = "msg error";
        setupMsg.textContent = data.error || "Verification failed";
        confirmSetupBtn.disabled = false;
        return;
      }

      setupMsg.className = "msg success";
      setupMsg.textContent = "2FA enabled!";
      setTimeout(() => location.reload(), 1500);
    } catch (err) {
      setupMsg.className = "msg error";
      setupMsg.textContent = "Network error: " + err.message;
      confirmSetupBtn.disabled = false;
    }
  });

  // Disable 2FA
  disableBtn.addEventListener("click", async function () {
    if (!confirm("Disable two-factor authentication?")) return;
    disableBtn.disabled = true;

    try {
      const response = await fetch("/api/auth/2fa/disable", { method: "POST" });
      if (!response.ok) {
        alert("Failed to disable 2FA");
        disableBtn.disabled = false;
        return;
      }
      location.reload();
    } catch (err) {
      alert("Network error: " + err.message);
      disableBtn.disabled = false;
    }
  });

  // Logout
  logoutBtn.addEventListener("click", async function () {
    try {
      await fetch("/api/auth/logout", { method: "POST" });
      window.location.href = "/index.html";
    } catch (err) {
      console.error("Logout error:", err);
    }
  });
});

// Load QR code library (qrcode npm package)
const QRCode = (() => {
  const script = document.createElement("script");
  script.src = "https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js";
  document.head.appendChild(script);

  return {
    toSvg: function (data, callback) {
      script.onload = function () {
        const qr = new window.QRCode({
          text: data,
          width: 200,
          height: 200,
          correctLevel: window.QRCode.CorrectLevel.H,
          useSVG: true,
        });
        const svg = qr._el.querySelector("svg");
        callback(null, svg);
      };
    },
  };
})();
