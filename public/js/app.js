// public/js/app.js
// Handles login/register form switching, submission, and authentication flow.

document.addEventListener("DOMContentLoaded", function () {
  // Tab switching
  const tabLogin = document.getElementById("tabLogin");
  const tabRegister = document.getElementById("tabRegister");
  const loginForm = document.getElementById("loginForm");
  const registerForm = document.getElementById("registerForm");
  const heading = document.getElementById("heading");

  tabLogin.addEventListener("click", function () {
    tabLogin.classList.add("active");
    tabRegister.classList.remove("active");
    loginForm.style.display = "block";
    registerForm.style.display = "none";
    heading.textContent = "Sign in to your account";
  });

  tabRegister.addEventListener("click", function () {
    tabRegister.classList.add("active");
    tabLogin.classList.remove("active");
    loginForm.style.display = "none";
    registerForm.style.display = "block";
    heading.textContent = "Create a new account";
  });

  // Registration
  registerForm.addEventListener("submit", async function (e) {
    e.preventDefault();
    const form = new FormData(registerForm);
    const registerSubmit = document.getElementById("registerSubmit");
    const registerMsg = document.getElementById("registerMsg");

    registerSubmit.disabled = true;
    registerMsg.className = "msg";
    registerMsg.textContent = "Creating account...";

    try {
      const response = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: form.get("username"),
          email: form.get("email"),
          password: form.get("password"),
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        registerMsg.className = "msg error";
        registerMsg.textContent = data.error || "Registration failed";
        return;
      }

      registerMsg.className = "msg success";
      registerMsg.textContent = "Account created! Redirecting to login...";
      registerForm.reset();
      setTimeout(() => window.location.reload(), 1500);
    } catch (err) {
      registerMsg.className = "msg error";
      registerMsg.textContent = "Network error: " + err.message;
    } finally {
      registerSubmit.disabled = false;
    }
  });

  // Login
  loginForm.addEventListener("submit", async function (e) {
    e.preventDefault();
    const form = new FormData(loginForm);
    const loginSubmit = document.getElementById("loginSubmit");
    const loginMsg = document.getElementById("loginMsg");
    const tokenField = document.getElementById("tokenField");

    loginSubmit.disabled = true;
    loginMsg.className = "msg";
    loginMsg.textContent = "Logging in...";

    try {
      const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          username: form.get("username"),
          password: form.get("password"),
          token: form.get("token") || undefined,
        }),
      });

      const data = await response.json();

      if (!response.ok) {
        if (data.requiresTOTP) {
          loginMsg.className = "msg info";
          loginMsg.textContent = "Enter your 2FA code:";
          tokenField.style.display = "block";
          loginForm.reset();
          document.getElementById("loginUsername").focus();
        } else {
          loginMsg.className = "msg error";
          loginMsg.textContent = data.error || "Login failed";
          tokenField.style.display = "none";
        }
        return;
      }

      loginMsg.className = "msg success";
      loginMsg.textContent = "Login successful! Redirecting...";
      setTimeout(() => (window.location.href = "/dashboard.html"), 1500);
    } catch (err) {
      loginMsg.className = "msg error";
      loginMsg.textContent = "Network error: " + err.message;
      tokenField.style.display = "none";
    } finally {
      loginSubmit.disabled = false;
    }
  });
});
