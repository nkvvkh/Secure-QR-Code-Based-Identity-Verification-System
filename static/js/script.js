/* script.js - menu toggle, confirm dialogs, and the QR scanner / verifier page. */
document.addEventListener("DOMContentLoaded", () => {
  const toggle = document.getElementById("nav-toggle");
  const links = document.getElementById("nav-links");
  if (toggle && links) toggle.addEventListener("click", () => links.classList.toggle("open"));

  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });

  if (document.getElementById("verify-app")) initVerifier();
});

function initVerifier() {
  const csrf = document.querySelector('meta[name="csrf-token"]').content;
  const video = document.getElementById("video");
  const canvas = document.getElementById("canvas");
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  const startBtn = document.getElementById("start-camera");
  const stopBtn = document.getElementById("stop-camera");
  const camStatus = document.getElementById("camera-status");
  const fileInput = document.getElementById("qr-file");
  const manualText = document.getElementById("manual-text");
  const manualBtn = document.getElementById("manual-verify");
  const resultBox = document.getElementById("result");
  const resultBadge = document.getElementById("result-badge");
  const resultMsg = document.getElementById("result-message");
  const resultDetails = document.getElementById("result-details");

  let stream = null;
  let scanning = false;
  let busy = false;

  // ---- show the server's answer (textContent only, so nothing can inject HTML)
  function showResult(data) {
    const result = (data.result || "ERROR").toUpperCase();
    resultBox.className = "result result-" + result.toLowerCase();
    resultBadge.textContent = result;
    resultMsg.textContent = data.message || "";
    resultDetails.textContent = "";
    if (data.user) {
      const labels = [["Name", data.user.name], ["User ID", data.user.user_id],
                      ["Department", data.user.department], ["Expires", data.user.expiry_date]];
      labels.forEach(([label, value]) => {
        const dt = document.createElement("dt"); dt.textContent = label;
        const dd = document.createElement("dd"); dd.textContent = value;
        resultDetails.append(dt, dd);
      });
      resultDetails.hidden = false;
    } else {
      resultDetails.hidden = true;
    }
  }

  async function sendPayload(payload) {
    if (busy) return;
    busy = true;
    try {
      const response = await fetch("/api/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
        body: JSON.stringify({ payload }),
      });
      showResult(await response.json());
    } catch (err) {
      showResult({ result: "ERROR", message: "Could not reach the server. Is it running?" });
    } finally {
      busy = false;
    }
  }

  // ---- webcam scanning
  async function startCamera() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      camStatus.textContent = "Camera not supported here. Use the image upload instead.";
      return;
    }
    try {
      stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } });
      video.srcObject = stream;
      await video.play();
      scanning = true;
      startBtn.disabled = true; stopBtn.disabled = false;
      camStatus.textContent = "Scanning... hold the QR code in front of the camera.";
      requestAnimationFrame(scanFrame);
    } catch (err) {
      camStatus.textContent = "Could not open the camera (" + err.name + "). Allow camera access or upload an image.";
    }
  }

  function stopCamera() {
    scanning = false;
    if (stream) stream.getTracks().forEach((track) => track.stop());
    stream = null; video.srcObject = null;
    startBtn.disabled = false; stopBtn.disabled = true;
  }

  function scanFrame() {
    if (!scanning) return;
    if (video.readyState === video.HAVE_ENOUGH_DATA && video.videoWidth > 0) {
      canvas.width = video.videoWidth; canvas.height = video.videoHeight;
      ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
      const img = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(img.data, img.width, img.height, { inversionAttempts: "dontInvert" });
      if (code && code.data) {
        stopCamera();
        camStatus.textContent = "QR code detected. Camera stopped.";
        sendPayload(code.data);
        return;
      }
    }
    requestAnimationFrame(scanFrame);
  }

  // ---- image upload
  fileInput.addEventListener("change", () => {
    const file = fileInput.files[0];
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) { showResult({ result: "ERROR", message: "Image is too large (max 5 MB)." }); return; }
    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = () => {
      const scale = Math.min(1, 1200 / Math.max(img.width, img.height));
      canvas.width = Math.round(img.width * scale); canvas.height = Math.round(img.height * scale);
      ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
      URL.revokeObjectURL(url);
      const data = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(data.data, data.width, data.height, { inversionAttempts: "attemptBoth" });
      if (code && code.data) sendPayload(code.data);
      else showResult({ result: "INVALID", message: "No QR code could be found in that image." });
    };
    img.onerror = () => { URL.revokeObjectURL(url); showResult({ result: "ERROR", message: "That file is not a readable image." }); };
    img.src = url;
    fileInput.value = "";
  });

  // ---- pasted text (handy for testing tampered codes)
  manualBtn.addEventListener("click", () => {
    const text = manualText.value.trim();
    if (!text) { showResult({ result: "ERROR", message: "Paste the QR text first." }); return; }
    sendPayload(text);
  });

  startBtn.addEventListener("click", startCamera);
  stopBtn.addEventListener("click", () => { stopCamera(); camStatus.textContent = "Camera is off."; });
  window.addEventListener("beforeunload", stopCamera);
}
