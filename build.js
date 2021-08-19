const ENCRYPT_FUNCTION_STATIC = `{COMMON_JS}

async function encryptId(folderId) {
  return encrypt(folderId, "{KEY}");
}`;

const ENCRYPT_FUNCTION_SERVER = `async function encryptId(folderId) {
  const result = await fetch("encrypt", {method: "POST", body: JSON.stringify({folder: folderId})});
  const data = await result.json();
  if(result.ok) {
    return data.data;
  }
  else {
    throw Error(data.reason);
  }
}`;
const ENCRYPT_PARSER = `
async function encrypt_(data) {
  return encrypt(data.folder, KEY);
}
`;
const ENCRYPT_GET = `
  else if(request.method === "GET" && request.url.endsWith("/encrypt")) {
    return new Response(\`{ENCRYPT_HTML}\`, {status: 200, headers: {"Content-Type": "text/html; charset=UTF-8"}});
  }`;
const ENCRYPT_POST = `
  else if(request.url.endsWith("/encrypt")) {
    parser = encrypt_;
  }`;

const saveAsFile = (filename, blob) => {
  const a = document.createElement("a");
  const url = window.URL.createObjectURL(blob);
  a.href = url;
  a.download = filename;
  a.style = "display: none";
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(url);
  a.remove();
};

const parseLines = text => {
  const goodLines = new Set();
  for(const [, url] of text.matchAll(/^\s*(https?:\/\/.+?)\s*$/gm)) {
    goodLines.add(url);
  }
  return goodLines;
};

const parseServer = url => {
  const m = url.match(/^(https?):\/\/(.+?)\/?$/);
  if(m[1] === "https") {
    return m[2];
  }
  else { // this must be http, `parseLines` won't allow anything else
    return `i:${m[2]}`;
  }
};

const parseServerList = url => {
  let m = url.match(/^https:\/\/gist\.(?:github|githubusercontent)\.com\/([^\/]+\/[0-9a-f]+)\/raw\/[0-9a-f]+\/(.+?)$/);
  if(m !== null) {
    return `g:${m[1]}<${m[2]}`;
  }
  m = url.match(/^https:\/\/p\.teknik\.io\/Raw\/(.+?)$/);
  if(m !== null) {
    return `t:${m[1]}`;
  }
  m = url.match(/^https:\/\/pastebin\.com\/raw\/(.+?)$/);
  if(m !== null) {
    return `p:${m[1]}`;
  }

  m = url.match(/^(https?):\/\/(.+?)$/);
  if(m[1] === "https") {
    return `l:${m[2]}`;
  }
  else { // this must be http, `parseLines` won't allow anything else
    return `k:${m[2]}`;
  }
};

const getFile = async path => {
  return (await fetch(path)).text();
};

const addSection = (name, content) => `<h3>${name}</h3><pre>${content}</pre>`;

const parseForm = async () => {
  const ALLOW_SITES = "*";

  const decryptServers = parseLines($("#decrypt_servers").val());
  const decryptServerLists = parseLines($("#decrypt_server_lists").val());
  const urlsAndOptions = [];
  for(const url of decryptServers) {
    urlsAndOptions.push(parseServer(url));
  }
  for(const url of decryptServerLists) {
    urlsAndOptions.push(parseServerList(url));
  }
  if(urlsAndOptions.length === 0) {
    throw Error("No decode servers");
  }
  const ENCODED_PREFIX = btoa(urlsAndOptions.join(";"));

  const KEY = $("#encryption_key").val();
  try {
    if(b64.base64ToBytes(KEY).length !== 32) {
      throw Error("wrong key length");
    }
  }
  catch(e) {
    throw Error(`Invalid encryption key; ${e.message}`);
  }

  const OPTIONS = [];
  if(decryptServers.size > 0) {
    OPTIONS.push(addSection("Decryption servers", Array.from(decryptServers).join("\n")));
  }
  if(decryptServerLists.size > 0) {
    OPTIONS.push(addSection("Decryption server lists", Array.from(decryptServerLists).join("\n")));
  }
  const OPTIONS_USED = `<div class="card-body">${OPTIONS.join("")}</div>`;

  const zip = new JSZip();
  zip.file("key.txt", KEY);

  const COMMON_JS = await getFile("common.js");
  const ENCRYPT_HTML = await getFile("templates/encrypt.html.template");

  zip.file("STATIC_ENCRYPTION/encrypt.html", ENCRYPT_HTML
    .replace("{ENCRYPT_FUNCTION}", ENCRYPT_FUNCTION_STATIC)
    .replace("{COMMON_JS}", COMMON_JS)
    .replace("{KEY}", KEY)
    .replace("{OPTIONS_USED}", OPTIONS_USED)
    .replace("{ENCODED_PREFIX}", ENCODED_PREFIX)
  );

  if($("#worker_decrypt").is(":checked")) {
    let DECRYPT_WORKER = await getFile("templates/worker.js.template");

    if($("#worker_encrypt").is(":checked")) {
      DECRYPT_WORKER = DECRYPT_WORKER
        .replace("{ENCRYPT_PARSER}", ENCRYPT_PARSER)
        .replace("{ENCRYPT_GET}", ENCRYPT_GET)
        .replace("{ENCRYPT_POST}", ENCRYPT_POST)
        .replace("{ENCRYPT_HTML}", ENCRYPT_HTML.replace(/\\/g, "\\\\"))
        .replace("{ENCRYPT_FUNCTION}", ENCRYPT_FUNCTION_SERVER)
        .replace("{OPTIONS_USED}", "")
        .replace("{ENCODED_PREFIX}", ENCODED_PREFIX);
    }
    else {
      DECRYPT_WORKER = DECRYPT_WORKER
        .replace("{ENCRYPT_PARSER}", "")
        .replace("{ENCRYPT_GET}", "")
        .replace("{ENCRYPT_POST}", "");
    }

    zip.file("WORKER/worker.js", DECRYPT_WORKER
      .replace("{COMMON_JS}", COMMON_JS)
      .replace("{KEY}", KEY)
      .replace("{ALLOW_SITES}", ALLOW_SITES)
    );
  }

  if($("#php_decrypt").is(":checked")) {
    const DECRYPT_PHP = await getFile("templates/decrypt.php.template");
    const ENCRYPT_PHP_FUNCTION = await getFile("templates/encrypt_function.php.template");
    zip.file("PHP/decrypt.php", DECRYPT_PHP
      .replace("{KEY}", KEY)
      .replace("{ENCRYPT_PHP_FUNCTION}", ENCRYPT_PHP_FUNCTION)
      .replace("{ALLOW_SITES}", ALLOW_SITES)
    );

    let htaccess = `Options -Indexes
RewriteEngine on
RewriteRule "^info$" "decrypt.php?page=info"
RewriteRule "^clone$" "decrypt.php?page=clone"
`;

    if($("#php_encrypt").is(":checked")) {
      htaccess += `RewriteRule "^encrypt$" "encrypt.php"
`;
      const ENCRYPT_PHP = await getFile("templates/encrypt.php.template");
      zip.file("PHP/encrypt.php", ENCRYPT_PHP
        .replace("{KEY}", KEY)
        .replace("{ENCRYPT_PHP_FUNCTION}", ENCRYPT_PHP_FUNCTION)
        .replace("{ENCRYPT_HTML}", ENCRYPT_HTML)
        .replace("{ENCRYPT_FUNCTION}", ENCRYPT_FUNCTION_SERVER)
        .replace("{OPTIONS_USED}", "")
        .replace("{ENCODED_PREFIX}", ENCODED_PREFIX)
      );
    }

    zip.file("PHP/.htaccess", htaccess);
  }

  const content = await zip.generateAsync({type:"blob"});
  saveAsFile("gd.zip", content);
};

$("#generate_key").click(async function(event) {
  event.preventDefault();

  $("#encryption_key").val(await generateKey());
});

$("#download_files").click(async function(event) {
  event.preventDefault();

  try {
    await parseForm();
  }
  catch(e) {
    console.error(e);
    alert(e.message);
  }
});

$("#worker_decrypt").change(function(event) {
  if(event.delegateTarget.checked) {
    $("#worker_encrypt").removeAttr("disabled");
  }
  else {
    $("#worker_encrypt").attr("disabled", "").prop("checked", false);
  }
});

$("#php_decrypt").change(function(event) {
  if(event.delegateTarget.checked) {
    $("#php_encrypt").removeAttr("disabled");
  }
  else {
    $("#php_encrypt").attr("disabled", "").prop("checked", false);
  }
});
