/* QR Scanner — BarcodeDetector when the browser has it, else jsQR (Cosmo Wolfe, Apache-2.0). Links never open by themselves. */
(function () {
  "use strict";
  var $ = S3.$, h = S3.h;
  var video = $("#video"), work = $("#work"), wctx = work.getContext("2d", { willReadFrequently: true });
  var st = { stream: null, detector: null, devices: [], devIdx: 0, torch: false, last: "", lastAt: 0, busy: false, frame: 0, current: null };
  var history = S3.store("qrscan.history") || [];
  var keep = S3.store("qrscan.keep") !== false;

  // ---------- decoding ----------
  function decodeImageData(img, both) {
    var r = jsQR(img.data, img.width, img.height, { inversionAttempts: both ? "attemptBoth" : "dontInvert" });
    return r ? r.data : null;
  }
  function grab(src, sw, sh, max) {
    var k = Math.min(1, max / Math.max(sw, sh)), w = Math.max(1, Math.round(sw * k)), hh = Math.max(1, Math.round(sh * k));
    work.width = w; work.height = hh;
    wctx.drawImage(src, 0, 0, w, hh);
    return wctx.getImageData(0, 0, w, hh);
  }
  function detectorReady() {
    if (!("BarcodeDetector" in window)) return Promise.resolve(null);
    return window.BarcodeDetector.getSupportedFormats().then(function (f) {
      return f.indexOf("qr_code") >= 0 ? new window.BarcodeDetector({ formats: ["qr_code"] }) : null;
    }).catch(function () { return null; });
  }
  function viaDetector(src) {
    if (!st.detector) return Promise.resolve(null);
    return st.detector.detect(src).then(function (c) { return c.length ? c[0].rawValue : null; }).catch(function () { return null; });
  }
  function decodeBitmap(bmp) {
    return viaDetector(bmp).then(function (txt) {
      if (txt != null) return txt;
      var sizes = [1600, 900, 500];
      for (var i = 0; i < sizes.length; i++) {
        var t = decodeImageData(grab(bmp, bmp.width, bmp.height, sizes[i]), true);
        if (t != null) return t;
      }
      return null;
    });
  }

  // ---------- parsing ----------
  function splitEsc(s, sep) { // split on unescaped sep, keeping escapes for the next step
    var out = [], cur = "";
    for (var i = 0; i < s.length; i++) {
      var c = s[i];
      if (c === "\\" && i + 1 < s.length) { cur += c + s[++i]; continue; }
      if (c === sep) { out.push(cur); cur = ""; } else cur += c;
    }
    out.push(cur);
    return out;
  }
  function unesc(s) { return s.replace(/\\(.)/g, "$1"); }
  function kv(body) { // "K:V;K:V;;" -> {K: [V, …]}
    var o = {};
    splitEsc(body, ";").forEach(function (f) {
      var i = f.indexOf(":"); if (i < 1) return;
      var k = f.slice(0, i).toUpperCase(); (o[k] = o[k] || []).push(unesc(f.slice(i + 1)));
    });
    return o;
  }
  function vcard(text) {
    var o = {};
    text.replace(/\r?\n[ \t]/g, "").split(/\r?\n/).forEach(function (line) {
      var i = line.indexOf(":"); if (i < 1) return;
      var key = line.slice(0, i).split(";")[0].toUpperCase().replace(/^ITEM\d+\./, "");
      var val = line.slice(i + 1).replace(/\\n/gi, "\n").replace(/\\([,;\\])/g, "$1");
      (o[key] = o[key] || []).push(val);
    });
    return o;
  }
  function analyzeUrl(raw) {
    var s = raw.trim(), u;
    if (/^www\./i.test(s)) s = "https://" + s;
    try { u = new URL(s); } catch (e) { return null; }
    var web = u.protocol === "https:" || u.protocol === "http:", warn = [];
    if (!web) return { href: u.href, protocol: u.protocol, host: u.host, openable: false, warn: ["Uses the “" + u.protocol + "” scheme, which isn't a web page. It can't be opened from here."] };
    if (u.protocol === "http:") warn.push("Not encrypted (http). Anyone on the network could see or change this page.");
    if (u.username || u.password) warn.push("The link hides text before an @ sign. The real site is " + u.hostname + ", not what comes before the @.");
    if (/(^|\.)xn--/i.test(u.hostname)) warn.push("International domain shown in its real form (" + u.hostname + "). Lookalike letters are a common phishing trick.");
    if (/^\d{1,3}(\.\d{1,3}){3}$|^\[/.test(u.hostname)) warn.push("Points to a bare IP address instead of a named website.");
    if (u.port) warn.push("Uses an unusual port (" + u.port + ").");
    return { href: u.href, protocol: u.protocol, host: u.hostname, rest: (u.port ? ":" + u.port : "") + u.pathname + u.search + u.hash, openable: true, warn: warn };
  }
  function classify(text) {
    var t = text.trim(), up = t.toUpperCase();
    if (/^https?:\/\//i.test(t) || /^www\.[^\s]+\.[^\s]+$/i.test(t)) { var u = analyzeUrl(t); if (u) return { type: "Link", url: u }; }
    if (up.indexOf("WIFI:") === 0) {
      var w = kv(t.slice(5));
      return { type: "Wi-Fi", rows: [["Network", (w.S || [""])[0]], ["Password", (w.P || [""])[0], true], ["Security", (w.T || ["none"])[0] || "none"], ["Hidden", w.H && /true/i.test(w.H[0]) ? "Yes" : "No"]] };
    }
    if (up.indexOf("BEGIN:VCARD") === 0) {
      var v = vcard(t), rows = [];
      var name = (v.FN || [])[0] || (v.N ? v.N[0].split(";").slice(0, 2).reverse().join(" ").trim() : "");
      if (name) rows.push(["Name", name]);
      [["ORG", "Company"], ["TITLE", "Title"], ["TEL", "Phone"], ["EMAIL", "Email"], ["URL", "Website"], ["ADR", "Address"], ["NOTE", "Note"]].forEach(function (p) {
        (v[p[0]] || []).forEach(function (x) { x = p[0] === "ADR" || p[0] === "ORG" ? x.split(";").filter(Boolean).join(", ") : x; if (x) rows.push([p[1], x, true]); });
      });
      return { type: "Contact", rows: rows, vcf: t };
    }
    if (up.indexOf("MECARD:") === 0) {
      var m = kv(t.slice(7)), mr = [];
      if (m.N) mr.push(["Name", m.N[0].split(",").reverse().join(" ").trim()]);
      (m.TEL || []).forEach(function (x) { mr.push(["Phone", x, true]); });
      (m.EMAIL || []).forEach(function (x) { mr.push(["Email", x, true]); });
      (m.URL || []).forEach(function (x) { mr.push(["Website", x, true]); });
      (m.ADR || []).forEach(function (x) { mr.push(["Address", x, true]); });
      return { type: "Contact", rows: mr };
    }
    if (/^mailto:/i.test(t)) {
      var q = t.slice(7).split("?"), p = new URLSearchParams(q[1] || ""), er = [["To", decodeURIComponent(q[0]), true]];
      if (p.get("subject")) er.push(["Subject", p.get("subject")]);
      if (p.get("body")) er.push(["Message", p.get("body"), true]);
      return { type: "Email", rows: er };
    }
    if (up.indexOf("MATMSG:") === 0) {
      var mm = kv(t.slice(7));
      return { type: "Email", rows: [["To", (mm.TO || [""])[0], true], ["Subject", (mm.SUB || [""])[0]], ["Message", (mm.BODY || [""])[0], true]] };
    }
    if (/^tel:/i.test(t)) return { type: "Phone", rows: [["Number", t.slice(4), true]] };
    if (/^smsto:/i.test(t)) { var sp = t.slice(6), ci = sp.indexOf(":"); return { type: "SMS", rows: [["To", ci < 0 ? sp : sp.slice(0, ci), true], ["Message", ci < 0 ? "" : sp.slice(ci + 1), true]] }; }
    if (/^sms:/i.test(t)) { var sq = t.slice(4).split("?"); return { type: "SMS", rows: [["To", sq[0], true], ["Message", new URLSearchParams(sq[1] || "").get("body") || "", true]] }; }
    if (/^geo:/i.test(t)) {
      var g = /^geo:(-?[\d.]+),(-?[\d.]+)/i.exec(t);
      if (g) return { type: "Location", rows: [["Latitude", g[1], true], ["Longitude", g[2], true], ["Both", g[1] + ", " + g[2], true]] };
    }
    if (up.indexOf("BEGIN:VEVENT") === 0 || up.indexOf("BEGIN:VCALENDAR") === 0) {
      var e = vcard(t);
      return { type: "Event", rows: [["Title", (e.SUMMARY || [""])[0]], ["Starts", (e.DTSTART || [""])[0]], ["Ends", (e.DTEND || [""])[0]], ["Where", (e.LOCATION || [""])[0]]].filter(function (r) { return r[1]; }) };
    }
    if (/^[a-z][a-z0-9+.-]{1,20}:\S/i.test(t) && !/\s/.test(t)) { var other = analyzeUrl(t); if (other) return { type: "Link", url: other }; }
    return { type: "Text" };
  }

  // ---------- result view ----------
  function copyBtn(text, label) {
    return h("button", { "class": "btn small", onclick: function () { S3.copy(text, label || "Copied"); } }, [svgIcon("copy"), "Copy"]);
  }
  function svgIcon(name) { var s = document.createElementNS("http://www.w3.org/2000/svg", "svg"); s.setAttribute("class", "i"); var u = document.createElementNS("http://www.w3.org/2000/svg", "use"); u.setAttribute("href", "#i-" + name); s.appendChild(u); return s; }

  function show(text) {
    var c = classify(text), box = $("#result");
    st.current = text;
    $("#rtype").className = "chip accent"; $("#rtype").textContent = c.type;
    box.innerHTML = "";
    if (c.url) {
      var u = c.url, card = h("div", { "class": "url-box" });
      card.appendChild(h("div", { "class": "faint", text: u.openable ? "This link goes to" : "Link" }));
      card.appendChild(h("div", { "class": "url-host", dir: "ltr", text: u.host || u.protocol }));
      card.appendChild(h("div", { "class": "url-full mono", dir: "ltr" }, [h("span", { "class": "muted", text: u.protocol + "//" }), h("b", { text: u.host }), h("span", { "class": "muted", text: u.rest || "" })]));
      if (u.protocol === "https:" && !u.warn.length) card.appendChild(h("span", { "class": "chip ok", text: "Encrypted (https)" }));
      u.warn.forEach(function (w) { card.appendChild(h("div", { "class": "url-warn", text: "⚠ " + w })); });
      var row = h("div", { "class": "row mt" });
      if (u.openable) row.appendChild(h("a", { "class": "btn primary", href: u.href, target: "_blank", rel: "noopener noreferrer", onclick: function () { S3.done(); } }, [svgIcon("play"), "Open link"]));
      row.appendChild(copyBtn(u.href, "Link copied"));
      card.appendChild(row);
      box.appendChild(card);
      if (u.openable) box.appendChild(h("p", { "class": "faint", text: "Only open links you trust. Check the site name above, not the text around the QR code." }));
    } else if (c.rows) {
      var tb = h("tbody");
      c.rows.forEach(function (r) {
        tb.appendChild(h("tr", null, [h("th", { text: r[0] }), h("td", { dir: "auto", text: r[1] || "—" }), h("td", { "class": "act" }, [r[2] && r[1] ? copyBtn(r[1], r[0] + " copied") : null])]));
      });
      box.appendChild(h("div", { "class": "tbl-wrap" }, [h("table", { "class": "tbl kv" }, [tb])]));
      if (c.vcf) box.appendChild(h("div", { "class": "row mt" }, [h("button", { "class": "btn", onclick: function () { S3.download(c.vcf, "contact.vcf", "text/vcard"); S3.done(); } }, [svgIcon("download"), "Save contact (.vcf)"])]));
    }
    box.appendChild(h("div", { "class": "row between mt" }, [h("span", { "class": "faint", text: "Raw content · " + text.length + " characters" }), copyBtn(text, "Text copied")]));
    box.appendChild(h("pre", { "class": "out raw", dir: "auto", text: text }));
  }

  // ---------- history ----------
  function addHistory(text, save) {
    history = history.filter(function (x) { return x.t !== text; });
    history.unshift({ t: text, k: classify(text).type, at: Date.now() });
    history = history.slice(0, 50);
    if (keep && save !== false) S3.store("qrscan.history", history);
    drawHistory();
  }
  function drawHistory() {
    var ul = $("#hist"); ul.innerHTML = "";
    $("#hcount").textContent = history.length ? history.length + " saved" : "";
    if (!history.length) { ul.appendChild(h("li", { "class": "empty" }, [keep ? "Scans you make show up here, saved only in this browser." : "History is off. Scans aren't saved."])); return; }
    history.forEach(function (x) {
      ul.appendChild(h("li", null, [h("button", { "class": "hist-item", onclick: function () { show(x.t); $("#resultCard").scrollIntoView({ behavior: "smooth", block: "nearest" }); } }, [
        h("span", { "class": "chip", text: x.k }), h("span", { "class": "hist-t", dir: "auto", text: x.t.replace(/\s+/g, " ") }), h("span", { "class": "faint", text: new Date(x.at).toLocaleString() })
      ])]));
    });
  }
  $("#keep").checked = keep;
  $("#keep").addEventListener("change", function (e) {
    keep = e.target.checked; S3.store("qrscan.keep", keep);
    if (!keep) { history = []; S3.store("qrscan.history", undefined); S3.toast("History off and cleared"); } else S3.store("qrscan.history", history);
    drawHistory();
  });
  $("#hclear").addEventListener("click", function () { history = []; S3.store("qrscan.history", undefined); drawHistory(); S3.toast("History cleared"); });

  function found(text, fromCam) {
    var now = Date.now();
    if (fromCam && text === st.last && now - st.lastAt < 4000) return;
    st.last = text; st.lastAt = now;
    show(text); addHistory(text);
    if (fromCam) { $("#cam").classList.add("hit"); setTimeout(function () { $("#cam").classList.remove("hit"); }, 500); if (navigator.vibrate) navigator.vibrate(40); }
    S3.done();
  }

  // ---------- camera ----------
  function camError(e) {
    var n = e && e.name;
    S3.toast(n === "NotAllowedError" ? "Camera permission was denied. Allow it in the address bar, or scan an image instead." :
      n === "NotFoundError" || n === "OverconstrainedError" ? "No camera found on this device." :
      n === "NotReadableError" ? "The camera is busy in another app." : "Couldn't start the camera.", "error");
    stopCam();
  }
  function startCam() {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) { S3.toast("Camera needs a secure (https) page and a modern browser.", "error"); return; }
    var dev = st.devices[st.devIdx];
    var c = dev ? { deviceId: { exact: dev.deviceId } } : { facingMode: { ideal: "environment" }, width: { ideal: 1280 }, height: { ideal: 720 } };
    stopTracks();
    navigator.mediaDevices.getUserMedia({ video: c, audio: false }).then(function (stream) {
      st.stream = stream; video.srcObject = stream;
      $("#cam").hidden = false; $("#startBox").hidden = true;
      return video.play().then(function () {
        var track = stream.getVideoTracks()[0], caps = track.getCapabilities ? track.getCapabilities() : {};
        $("#torch").hidden = !caps.torch; st.torch = false; $("#torch").setAttribute("aria-pressed", "false");
        if (!dev) { var s = track.getSettings ? track.getSettings() : {}; st.curId = s.deviceId; }
        return navigator.mediaDevices.enumerateDevices().then(function (list) {
          st.devices = list.filter(function (d) { return d.kind === "videoinput"; });
          if (!dev && st.curId) st.devIdx = Math.max(0, st.devices.map(function (d) { return d.deviceId; }).indexOf(st.curId));
          $("#flip").hidden = st.devices.length < 2;
        });
      }).then(function () { requestAnimationFrame(loop); });
    }).catch(camError);
  }
  function stopTracks() { if (st.stream) st.stream.getTracks().forEach(function (t) { t.stop(); }); st.stream = null; }
  function stopCam() { stopTracks(); video.srcObject = null; $("#cam").hidden = true; $("#startBox").hidden = false; }
  function loop() {
    if (!st.stream) return;
    if (!st.busy && video.readyState >= 2 && video.videoWidth) {
      st.busy = true; st.frame++;
      var p = st.detector ? viaDetector(video) : Promise.resolve(decodeImageData(grab(video, video.videoWidth, video.videoHeight, 800), st.frame % 3 === 0));
      p.then(function (t) { if (t != null && st.stream) found(t, true); }).finally(function () { st.busy = false; });
    }
    setTimeout(function () { requestAnimationFrame(loop); }, 90);
  }
  $("#start").addEventListener("click", startCam);
  $("#stop").addEventListener("click", stopCam);
  $("#flip").addEventListener("click", function () { st.devIdx = (st.devIdx + 1) % st.devices.length; startCam(); });
  $("#torch").addEventListener("click", function () {
    if (!st.stream) return;
    st.torch = !st.torch;
    st.stream.getVideoTracks()[0].applyConstraints({ advanced: [{ torch: st.torch }] }).then(function () {
      $("#torch").setAttribute("aria-pressed", String(st.torch));
    }).catch(function () { st.torch = false; S3.toast("This camera can't use the torch", "error"); });
  });
  document.addEventListener("visibilitychange", function () { if (document.hidden && st.stream) stopCam(); });

  // ---------- images ----------
  function scanFile(file) {
    if (!file || !/^image\//.test(file.type)) { S3.toast("That isn't an image", "error"); return; }
    createImageBitmap(file).then(decodeBitmap).then(function (t) {
      if (t == null) S3.toast("No QR code found. Try a sharper, closer or uncropped image.", "error"); else found(t, false);
    }).catch(function () { S3.toast("Couldn't read that image", "error"); });
  }
  S3.drop($("#drop"), function (files) { scanFile(files[0]); }, { accept: "image/*", multiple: false });
  document.addEventListener("paste", function (e) {
    var items = (e.clipboardData && e.clipboardData.items) || [];
    for (var i = 0; i < items.length; i++) if (items[i].kind === "file" && /^image\//.test(items[i].type)) { e.preventDefault(); scanFile(items[i].getAsFile()); return; }
  });

  detectorReady().then(function (d) { st.detector = d; $("#engine").textContent = d ? "Engine: built-in detector" : "Engine: jsQR"; });
  drawHistory();

  // ---------- known QR for the self-test: "S3eidat QR test", version 2-M, rows as hex ----------
  var KNOWN = ["1fd737f", "104ad41", "175375d", "174045d", "1748e5d", "1050241", "1fd557f", "00e700", "146fd25", "1cb0ca9", "17f63d5", "89094b", "1dc9adb", "6a5367", "18c9ef7", "11f60b", "1f6cffb", "014f1a", "1fd615d", "1044b1b", "1747bf8", "1741290", "175dd37", "104f588", "1fd8dd1"];
  function drawKnown(scale, invert) {
    var n = KNOWN.length, px = (n + 8) * scale, c = document.createElement("canvas"); c.width = c.height = px;
    var x = c.getContext("2d", { willReadFrequently: true });
    x.fillStyle = invert ? "#000" : "#fff"; x.fillRect(0, 0, px, px); x.fillStyle = invert ? "#fff" : "#000";
    KNOWN.forEach(function (hex, r) { var v = parseInt(hex, 16); for (var col = 0; col < n; col++) if ((v >> (n - 1 - col)) & 1) x.fillRect((col + 4) * scale, (r + 4) * scale, scale, scale); });
    return x.getImageData(0, 0, px, px);
  }

  window.S3_DEMO = function () {
    ["WIFI:T:WPA;S:Café Guest;P:coffee-is-free;;", "BEGIN:VCARD\nVERSION:3.0\nFN:Sara Haddad\nTEL:+962790000000\nEND:VCARD", "Table 12 · Order at the counter"].forEach(function (t) { addHistory(t, false); });
    var t = "https://s3eidat.github.io/qr-studio/?ref=menu";
    show(t); addHistory(t, false);
  };

  window.S3_SELFTEST = function () {
    var ok = decodeImageData(drawKnown(6), false) === "S3eidat QR test" && decodeImageData(drawKnown(4, true), true) === "S3eidat QR test";
    var w = classify("WIFI:T:WPA;S:My\\;Net;P:pa\\:ss\\\\;H:true;;");
    var v = classify("BEGIN:VCARD\r\nVERSION:3.0\r\nN:Haddad;Sara;;;\r\nTEL;TYPE=CELL:+1 555\r\nEND:VCARD");
    var u1 = classify("http:" + "//user@xn--pple-43d.com:8080/x"), u2 = classify("https://s3eidat.github.io/a?b=1");
    var bad = analyzeUrl("data:text/html,hi");
    var m = classify("mailto:a@b.co?subject=Hi%20there");
    return ok && w.type === "Wi-Fi" && w.rows[0][1] === "My;Net" && w.rows[1][1] === "pa:ss\\" && w.rows[3][1] === "Yes" &&
      v.type === "Contact" && v.rows[0][1] === "Sara Haddad" && v.rows[1][1] === "+1 555" &&
      u1.type === "Link" && u1.url.warn.length === 4 && u1.url.host === "xn--pple-43d.com" &&
      u2.url.warn.length === 0 && u2.url.host === "s3eidat.github.io" && bad && bad.openable === false &&
      m.type === "Email" && m.rows[1][1] === "Hi there" && classify("hello world").type === "Text";
  };
})();
