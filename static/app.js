const form = document.getElementById("secret-form");
const nameInput = document.getElementById("name-input");
const messageInput = document.getElementById("message-input");
const statusBanner = document.getElementById("status-banner");
const decryptedList = document.getElementById("decrypted-list");
const rawTbody = document.getElementById("raw-tbody");

function escapeHtml(text) {
  const div = document.createElement("div");
  div.textContent = String(text ?? "");
  return div.innerHTML;
}

function showStatus(message, isError = false) {
  statusBanner.textContent = message;
  statusBanner.className = `status-banner ${isError ? "err" : "ok"}`;
}

async function loadDecryptedSecrets() {
  try {
    const res = await fetch("/api/secrets");
    const data = await res.json();
    const items = data.items || [];

    if (items.length === 0) {
      decryptedList.innerHTML = '<p class="empty-state">Belum ada data tersimpan di vault.</p>';
      return;
    }

    decryptedList.innerHTML = items
      .map((item) => {
        if (item.error) {
          return `
            <div class="record-item">
              <div class="record-top">
                <span class="record-name">#${item.id} — Error Dekripsi</span>
              </div>
              <div class="record-secret">${escapeHtml(item.error)}</div>
            </div>
          `;
        }
        return `
          <div class="record-item">
            <div class="record-top">
              <span class="record-name">#${item.id} — ${escapeHtml(item.name)}</span>
              <button class="btn btn-danger" onclick="deleteRecord(${item.id})">Hapus</button>
            </div>
            <div class="record-secret">${escapeHtml(item.secret_message)}</div>
            <div class="record-meta">
              Algoritma: ${escapeHtml(item.algorithm)} | Dibuat: ${escapeHtml(item.created_at)}
            </div>
          </div>
        `;
      })
      .join("");
  } catch (err) {
    decryptedList.innerHTML = `<p class="empty-state">Gagal memuat data: ${escapeHtml(err.message)}</p>`;
  }
}

async function loadRawCiphertext() {
  try {
    const res = await fetch("/api/secrets/raw");
    const data = await res.json();
    const records = data.records || [];

    if (records.length === 0) {
      rawTbody.innerHTML = '<tr><td colspan="5" class="empty-state">Tabel secrets masih kosong.</td></tr>';
      return;
    }

    rawTbody.innerHTML = records
      .map(
        (rec) => `
        <tr>
          <td>#${rec.id}</td>
          <td><code>${escapeHtml(rec.algorithm)}</code></td>
          <td class="mono-cell">${escapeHtml(rec.nonce_b64)}</td>
          <td class="mono-cell">${escapeHtml(rec.ciphertext_b64)}</td>
          <td>${escapeHtml(rec.created_at)}</td>
        </tr>
      `
      )
      .join("");
  } catch (err) {
    rawTbody.innerHTML = `<tr><td colspan="5" class="empty-state">Gagal memuat data mentah: ${escapeHtml(err.message)}</td></tr>`;
  }
}

async function deleteRecord(id) {
  await fetch(`/api/secrets/${id}`, { method: "DELETE" });
  await Promise.all([loadDecryptedSecrets(), loadRawCiphertext()]);
}

window.deleteRecord = deleteRecord;

form.addEventListener("submit", async (e) => {
  e.preventDefault();
  const payload = {
    name: nameInput.value.trim(),
    secret_message: messageInput.value.trim(),
  };

  try {
    const res = await fetch("/api/secrets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    const data = await res.json();

    if (!res.ok) {
      showStatus(data.error || "Gagal menyimpan data.", true);
      return;
    }

    showStatus(
      `Berhasil! Record #${data.record.id} dienkripsi (${data.record.algorithm}) dan disimpan ke SQLite.`
    );
    form.reset();
    await Promise.all([loadDecryptedSecrets(), loadRawCiphertext()]);
  } catch (err) {
    showStatus(`Kesalahan jaringan: ${err.message}`, true);
  }
});

document.getElementById("fill-sample-btn").addEventListener("click", () => {
  nameInput.value = "Operator_Alpha";
  messageInput.value = "RAHASIA_NEGARA_123";
});

document.getElementById("refresh-decrypted-btn").addEventListener("click", loadDecryptedSecrets);
document.getElementById("refresh-raw-btn").addEventListener("click", loadRawCiphertext);

Promise.all([loadDecryptedSecrets(), loadRawCiphertext()]);
