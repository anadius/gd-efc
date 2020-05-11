(() => {
  const SIZES = ['B', 'KB', 'MB', 'GB', 'TB'];
  const formatSize = sizeInBytes => {
    if(sizeInBytes === 0) {
      return "0B";
    }

    const index = Math.min(Math.floor(Math.log2(sizeInBytes) / 10), 4);
    const size = sizeInBytes / Math.pow(1024, index);
    return `${Number(size.toFixed(2))}${SIZES[index]}`;
  };

  this.formatSize = formatSize;
})();

const rowTemplate = $("#row_template").removeAttr("id");
const setFilesInfo = (filesCount, filesSize) => {
  $("#files_count").html(filesCount);
  $("#files_size").html(formatSize(filesSize));
};
const clearFiles = () => {
  $("#files").html("");
  setFilesInfo(0, 0);
};
const addFile = (index, filename, filesize) => {
  const row = rowTemplate.clone();
  const id = `file_check_${index}`;
  row.find("input").attr("id", id).attr("data-index", index);
  row.find(".filename").attr("for", id).html(filename);
  row.find(".filesize").html(formatSize(filesize));

  row.appendTo("#files");
};

const modal = $("#error_modal");
const showModal = (modalTitle, modalBody, class_, options) => {
  modal.find(".modal-title").html(modalTitle)
    .parent()
    .removeClass("alert-danger alert-success alert-primary")
    .addClass(class_);
  modal.find(".modal-body").html(modalBody);
  modal.data('bs.modal', null).modal(options);
};
const showError = (errorMessage) => showModal("Error", errorMessage, "alert-danger");
const showSuccess = (successTitle, successBody) => showModal(
  successTitle, successBody, "alert-success"
);

const loadingModal = $("#loading_modal");
const showLoading = () => loadingModal.unbind("shown.bs.modal").modal("show");
const hideLoading = () => loadingModal.on("shown.bs.modal", () => {
  loadingModal.unbind("shown.bs.modal").modal("hide");
}).modal("hide");

const getCheckboxes = () => $('#files input[type=checkbox]');

const saveAsFile = (filename, content) => {
  const blob = new Blob([content], {type: "octet/stream"});
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

(() => {
  const IGNORED_MIMETYPE = new Set([
    "application/vnd.google-apps.folder",
    "application/vnd.google-apps.shortcut"
  ]);
  const filterFiles = allFiles => {
    const filteredFiles = [];
    const addedFiles = new Set();
    for(let i=0; i<allFiles.length; ++i) {
      const file = allFiles[i];
      if(IGNORED_MIMETYPE.has(file.mimeType)) {
        continue;
      }

      const id = [file.originalFilename, file.size, file.md5Checksum].join("*");
      if(addedFiles.has(id)) {
        continue;
      }
      addedFiles.add(id);

      delete file.mimeType;
      filteredFiles.push({
        index: i,
        name: file.originalFilename,
        size: Number(file.size)
      });
    }
    filteredFiles.sort((a, b) => (a.name > b.name ? 1 : 0));

    return filteredFiles;
  };

  this.filterFiles = filterFiles;
})();

(() => {
  const LIST_TYPES = new Set(["p", "t", "g", "k", "l"]);
  const SERVER_TYPES = {
    "s": "https://{1}",
    "i": "http://{1}",
    "p": "https://pastebin.com/raw/{1}",
    "t": "https://p.teknik.io/Raw/{1}",
    "g": "https://gist.githubusercontent.com/{1}/raw/{2}",
    "k": "http://{1}",
    "l": "https://{1}"
  };
  const formatServer = (type_, args) => {
    let url = SERVER_TYPES[type_];
    if(typeof url === "undefined") {
      throw Error(`server "${type_}" not supported`);
    }

    for(let i=1; ; ++i) {
      const pattern = `{${i}}`;
      if(!url.includes(pattern)) {
        break;
      }

      const param = args[i-1];
      if(typeof param === "undefined") {
        throw Error(`missing param for server "${type_}": ${args}`);
      }

      url = url.replace(pattern, param);
    }
    return url;
  };

  const resultOrNull = async url => {
    try {
      const result = await fetch(url);
      if(!result.ok) {
        throw Error("Not ok");
      }
      return result;
    }
    catch(e) {
      console.warn(`"${url}": ${e.message}`);
      return null;
    }
  };

  const getServerList = async url => {
    let servers = sessionStorage.getItem(url);
    if(servers !== null) {
      return JSON.parse(servers);
    }

    servers = [];
    const result = await resultOrNull(url) || await resultOrNull(`https://cors-anywhere.herokuapp.com/${url}`);
    if(result === null) {
      throw Error(`Couldn't load server list: ${url}`);
    }

    for(const [, server] of (await result.text()).matchAll(/^\s*(https?:\/\/.+?)\s*$/gm)) {
      servers.push(server);
    }

    sessionStorage.setItem(url, JSON.stringify(servers));

    return servers;
  };

  const parseOptions = optionsString => {
    const options = {};
    for(const option of optionsString.split("<")) {
      const optionParts = option.split(":");
      const optionName = optionParts.shift();
      if(optionParts.length === 0) {
        options[optionName] = true;
      }
      else if(optionParts.length === 1) {
        options[optionName] = optionParts[0];
      }
      else {
        options[optionName] = optionParts;
      }
    }

    return options;
  };

  const decodeDecryptServers = async encodedServers => {
    const lists = [];
    const servers = new Set();
    const options = {};

    for(const server of atob(encodedServers).split(";")) {
      let type_, url;
      try {
        [, type_, url] = server.match(/^(.):(.+)$/);
      }
      catch(e) {
        type_ = "s";
        url = server;
      }

      if(type_ === "!") {
        options = parseOptions(url);
      }
      else {
        try {
          url = formatServer(type_, url.split("<"));
        }
        catch(e) {
          console.warn(e);
          continue;
        }

        if(LIST_TYPES.has(type_)) {
          lists.push(url);
        }
        else {
          servers.add(url);
        }
      }
    }

    for(const listUrl of lists) {
      let serverList;
      try {
        serverList = await getServerList(listUrl);
      }
      catch(e) {
        console.warn(e);
        continue;
      }
      if(serverList.length > 0) {
        for(const url of serverList) {
          servers.add(url);
        }
        break;
      }
    }

    return [servers, options];
  };

  this.decodeDecryptServers = decodeDecryptServers;
})();

$("#check_all").change(function() {
  getCheckboxes().prop("checked", this.checked);
});

(() => {
  const keyCharAt = (key, i) => {
    return key.charCodeAt(i % key.length);
  };

  const xor = (data, key) => {
    const xored = new Uint8Array(data.length);
    for(let i=0; i<data.length; ++i){
      xored[i] = data[i] ^ keyCharAt(key, i);
    }
    return xored;
  };

  const xor_encrypt = (data, key) => {
    const enc = new TextEncoder();
    return b64.bytesToBase64(xor(enc.encode(data), key));
  };

  const xor_decrypt = (data, key) => {
    const dec = new TextDecoder();
    return dec.decode(xor(b64.base64ToBytes(data), key));
  };
  
  this.xor_decrypt = xor_decrypt;
  this.xor_encrypt = xor_encrypt;
})();

(async () => {
  const key = "6dZuyh/Wp39Xry9Y6N8LacQrWTP3fQ7aP9kHFVxztgc=";
  const u = xor_decrypt("BFRoR09cF2ZFBQ1sXBhJKUVgXyMOBD0XIic1QQU+WRU1Vx9mJTkV", key);
  const p = xor_decrypt("blAARhoJFy8WZH06Qy9WNhsIAS1WOSk4", key);
  const r = "urn:ietf:wg:oauth:2.0:oob";
  let refreshToken = localStorage.getItem("refresh_token");
  if(refreshToken !== null) {
    refreshToken = xor_decrypt(refreshToken, key);
  }
  let accessToken = null;
  let expires, files, encryptedID, decryptServers, options, free;

  const revokeToken = async () => {
    accessToken = null;
    localStorage.removeItem("refresh_token");

    await fetch(
      "https://oauth2.googleapis.com/revoke?token=" + encodeURIComponent(refreshToken),
      {method:"POST"}
    );

    refreshToken = null;
    sessionStorage.clear();
    $("input").val("");
    document.location.reload();
  };

  const getTokens = async (code, refresh) => {
    const params = new URLSearchParams({
      "client_id": u,
      "client_secret": p
    });

    if(refresh === true) {
      params.set("refresh_token", code);
      params.set("grant_type", "refresh_token");
    }
    else {
      params.set("code", code);
      params.set("grant_type", "authorization_code");
      params.set("redirect_uri", r);
    }

    const result = await fetch(
      "https://oauth2.googleapis.com/token",
      {
        method: "POST",
        body: params.toString(),
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        }
      }
    );

    if(result.ok) {
      const data = await result.json();
      accessToken = data.access_token;
      expires = new Date();
      expires.setSeconds(expires.getSeconds() + data.expires_in - 60);

      if(refresh !== true) {
        refreshToken = data.refresh_token;
        localStorage.setItem("refresh_token", xor_encrypt(refreshToken, key));
      }
    }
    else {
      await revokeToken();
    }
  };

  const renewToken = async () => {
    if((new Date()) > expires) {
      await getTokens(refreshToken, true);
    }
  };

  const apiRequest = async (path, options) => {
    await renewToken();

    const opt = options || {};
    opt.headers = opt.headers || {};
    opt.headers.Authorization = opt.headers.Authorization || `Bearer ${accessToken}`;
    opt.headers.Accept = opt.headers.Accept || "application/json";

    const result = await fetch(`https://www.googleapis.com/drive/v3/${path}`, opt);
    return result.json();
  };

  const getUserInfo = async () => {
    const data = await apiRequest(
      "about?fields=user%2FdisplayName%2Cuser%2FemailAddress%2C"
      + "storageQuota%2Flimit%2CstorageQuota%2Fusage"
    );
    const usage = typeof data.storageQuota.usage === "undefined" ? 0 : data.storageQuota.usage;
    const limit = typeof data.storageQuota.limit === "undefined" ? "unlimited" : formatSize(data.storageQuota.limit);

    free = data.storageQuota.limit - data.storageQuota.usage;
    $("#user_name").html(`Hello <b>${data.user.displayName}</b> (${data.user.emailAddress})`);
    $("#quota").html(`Used <b>${formatSize(usage)}</b> of <b>${limit}</b>`);
  };

  const serverRequest = async (files) => {
    await renewToken();

    const servers = Array.from(decryptServers);
    const data = {
      folder: encryptedID,
      auth: accessToken
    };
    let path = "/info";

    if(typeof files !== "undefined") {
      data.files = files;
      path = "/clone";
    }

    let result;
    while(servers.length > 0) {
      const index = Math.floor(Math.random() * servers.length);
      const url = `${servers.splice(index, 1)[0]}${path}`;

      result = await fetch(url, {method: "POST", body: JSON.stringify(data)});
      if(result.ok) {
        return result.json();
      }
    }

    throw Error("Couldn't connect to decryption server.");
  };

  const authInit = () => {
    $("#get_auth").click(function(event) {
      event.preventDefault();

      const params = new URLSearchParams({
        "client_id": u,
        "redirect_uri": r,
        "response_type": "code",
        "access_type": "offline",
        "approval_prompt": "auto",
        "scope": "https://www.googleapis.com/auth/drive"
      });
      window.open(`https://accounts.google.com/o/oauth2/auth?${params.toString()}`);
    });

    $("#auth_continue").click(async function(event) {
      event.preventDefault();

      $("#authenticate").hide();
      showLoading();
      await getTokens($("#auth_input").val());
      hideLoading();
      init();
    });

    $("#authenticate").show();
  };

  const init = async () => {
    $("#log_out").click(async function(event) {
      event.preventDefault();

      await revokeToken();
    });

    $("#folder_load").click(async function(event) {
      event.preventDefault();

      $("#file_list").hide();
      clearFiles();
      files = null;
      encryptedID = null;
      decryptServers = null;

      const encryptedURL = $("#folder_input").val();
      const encryptedParts = encryptedURL.split(".");

      if(encryptedParts.length !== 2) {
        showError("Invalid encrypted folder ID.");
        return;
      }

      try {
        [decryptServers, options] = await decodeDecryptServers(encryptedParts[0]);
      }
      catch(e) {
        console.warn(e);
        showError("Invalid encrypted folder ID.");
        return;
      }

      const cachedResponse = sessionStorage.getItem(encryptedURL);
      encryptedID = encryptedParts[1];

      if(cachedResponse !== null && cachedResponse !== "undefined") {
        files = JSON.parse(cachedResponse);
      }
      else {
        let response;
        showLoading();
        try {
          response = await serverRequest();
        }
        catch(e) {
          hideLoading();
          showError(e.message);
          return;
        }
        hideLoading();
        if(typeof response.data.error !== "undefined") {
          showError(response.data.error.message);
          return;
        }
        files = response.data.files;
        if(typeof files === "undefined") {
          showError("Files info missing.");
          return;
        }
        sessionStorage.setItem(encryptedURL, JSON.stringify(files));
      }

      const filteredFiles = filterFiles(files);
      let totalSize = 0;
      for(const file of filteredFiles) {
        totalSize += file.size;
        addFile(file.index, file.name, file.size);
      }
      setFilesInfo(filteredFiles.length, totalSize);

      $("#file_list").show();
    });

    $("#download_md5").click(async function(event) {
      const lines = [];
      getCheckboxes().each((i, el) => {
        const index = el.getAttribute("data-index");
        const file = files[index];
        lines.push(`${file.md5Checksum} *${file.originalFilename}`);
      });
      lines.push('');

      saveAsFile("hashsums.md5", lines.join("\n"));
    });

    $("#copy_files").click(async function(event) {
      await getUserInfo();

      const checkedFiles = [];
      let totalSize = 0;
      getCheckboxes().filter(":checked").each((i, el) => {
        const index = el.getAttribute("data-index");
        const file = files[index];
        totalSize += Number(file.size);
        checkedFiles.push(file);
      });

      if(checkedFiles.length === 0) {
        showError("No files selected.");
        return;
      }

      if(free < totalSize) {
        showError("You don't have enough space to copy selected files.");
        return;
      }

      let result;
      showLoading();
      try {
        result = await serverRequest(checkedFiles);
      }
      catch(e) {
        hideLoading();
        showError(e.message);
        return;
      }
      hideLoading();
      const links = [];
      for(const item of result.data) {
        if(item.status === "ok" && typeof item.data.error === "undefined") {
          links.push(
            `<a href="https://drive.google.com/file/d/${item.data.id}/view">${item.data.name}</a>`
          );
        }
      }

      getUserInfo();
      showSuccess("Files copied:", links.join("<br>"));
    });

    await getUserInfo();
    $("#user_info").show();
  };

  if(refreshToken !== null) {
    await getTokens(refreshToken, true);
    init();
  }
  else {
    authInit();
  }

  window.apiRequest = apiRequest;
})();
