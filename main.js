// (async function() {

const SERVER_VERSION = 3;
const BLACKLIST = new Set([
  // add rogue servers here
]);
const key = "6dZuyh/Wp39Xry9Y6N8LacQrWTP3fQ7aP9kHFVxztgc=";
const accounts = {};
const IGNORED_MIMETYPE = new Set([
  "application/vnd.google-apps.folder",
  "application/vnd.google-apps.shortcut"
]);
const MIXED_CONTENT = `<p>This could be because of "mixed content". The page you're on is served over HTTPS and tries to connect to another page that's served over HTTP - and your browser doesn't like that.</p><p>If you're on <b>Chrome</b> - click on the padlock icon, "Site settings", scroll to the bottom of the page and set "Insecure content" to "Allow"</p><p class="text-center"><img src="images/chrome1.png"></p><p class="text-center"><img src="images/chrome2.png"></p><p>If you're on <b>Firefox</b> - click on the padlock icon, click that arrow next to the "Firefox has blocked..." message and then on "Disable protection for now".</p><p class="text-center"><img src="images/firefox1.png"></p><p class="text-center"><img src="images/firefox2.png"></p>`;

class ServerError extends Error {}

class Account {
  static async authenticate(code, refresh) {
    const acc = new Account();
    if(refresh) {
      acc.token = code;
    }
    await acc.getTokens(code, refresh);
    await acc.getUserInfo();
    acc.teamDrive = false;
    return acc;
  }

  get free() {
    return this.teamDrive ? Infinity : (this.limit - this.usage);
  }

  async serverRequest(server, folderId, files) {
    await this.renewToken();

    const data = {
      auth: this.accessToken
    };

    let path;
    if(typeof files === "undefined") {
      data.folder = folderId;
      path = "/info";
    }
    else {
      data.files = files;
      data.destination = this.folder;
      path = "/clone";
    }

    const result = await fetch(server + path, {method: "POST", body: JSON.stringify(data)});

    const text = await result.text();
    let responseData;
    try {
      responseData = JSON.parse(text);
    }
    catch(e) {
      throw Error(text);
    }

    const version = responseData.version || 1;
    if(version !== SERVER_VERSION) {
      const contact = version > SERVER_VERSION ? "runs this site" : "shared encrypted ID";
      throw new ServerError(`Decryption server is running version ${version} of the code, this page works with version ${SERVER_VERSION}. Contact the person who ${contact} and tell them to update the code.`);
    }

    if(responseData.status === "ok") {
      if(typeof responseData.data.error !== "undefined") {
        throw Error(responseData.data.error.message);
      }
      return responseData.data;
    }
    else if(responseData.status === "error") {
      throw new ServerError(responseData.reason);
    }
    else {
      throw Error(text);
    }
  }

  async cloneFile(fileId) {
    return this.apiRequest(
      `files/${fileId}/copy?supportsAllDrives=true&fields=id,size,name,webViewLink`,
      {
        headers: {
          "Content-Type": "application/json"
        },
        method: "POST",
        body: JSON.stringify({
          "parents": [this.folder],
          "appProperties": {
            "createdWithDdEfc": 1
          }
        })
      }
    );
  }
  async getFolder(folderId) {
    const folderInfo = await this.apiRequest(
      `files/${folderId}?supportsAllDrives=true&fields=name,mimeType,shortcutDetails/*`
    );

    let folderContents;
    // if it's a folder, grab the contents
    if(folderInfo.mimeType === "application/vnd.google-apps.folder") {
      folderContents = await this.apiRequest(
        `files?q="${folderId}"+in+parents`
        + "+and+mimeType+!%3D+'application%2Fvnd.google-apps.folder'"
        + "&fields=files(id,webViewLink,size,name,mimeType,md5Checksum,shortcutDetails/*)"
        + "&orderBy=name_natural&supportsAllDrives=true&includeItemsFromAllDrives=true"
      );
    }
    // if it's shortcut/file, set notLoaded to true and grab the info later
    else if(folderInfo.mimeType === "application/vnd.google-apps.shortcut") {
      folderContents = {
        files: [{
          notLoaded: true,
          id: folderInfo.shortcutDetails.targetId,
          mimeType: folderInfo.shortcutDetails.targetMimeType,
          name: folderInfo.name
        }]
      }
      delete folderInfo.shortcutDetails;
    }
    else {
      folderContents = {
        files: [{
          notLoaded: true,
          id: folderId,
          mimeType: folderInfo.mimeType,
          name: folderInfo.name
        }]
      }
    }
    delete folderInfo.mimeType;

    const files = [];
    for(const file of folderContents.files) {
      // set notLoaded to true for shortcuts
      if(file.mimeType === "application/vnd.google-apps.shortcut") {
        file.notLoaded = true;
        file.id = file.shortcutDetails.targetId;
        file.mimeType = file.shortcutDetails.targetMimeType;
      }

      let fileInfo;
      if(file.notLoaded === true) {
        fileInfo = await this.apiRequest(
          `files/${file.id}?supportsAllDrives=true&fields=webViewLink,size,md5Checksum`
        );
        fileInfo.id = file.id;
        fileInfo.mimeType = file.mimeType;
        fileInfo.name = file.name;
      }
      else {
        fileInfo = file;
      }

      files.push(fileInfo);
    }

    folderContents.files = files;

    const asd = Object.assign(folderContents, folderInfo);
    console.log(asd);
    return asd;
    // return Object.assign(folderContents, folderInfo);
  }

  async getMyFolder() {
    const data1 = await this.apiRequest(
      `files/${this.folder}?supportsAllDrives=true&fields=name,driveId,`
      + "capabilities/canAddChildren,capabilities/canRemoveChildren,"
      + "capabilities/canDeleteChildren,capabilities/canTrashChildren"
    );

    if(!data1.capabilities.canAddChildren) {
      throw Error("Not a folder or can't create new files there.");
    }

    this.teamDrive = typeof data1.driveId !== "undefined";
    if(this.teamDrive) {
      data1.canDelete = data1.capabilities.canDeleteChildren;
      data1.canTrash = data1.capabilities.canTrashChildren;
      const driveData = await this.apiRequest(
        `drives/${data1.driveId}?fields=name,restrictions/domainUsersOnly,restrictions/driveMembersOnly`
      );
      data1.canShare = !(driveData.restrictions.domainUsersOnly || driveData.restrictions.driveMembersOnly);
      if(this.folder === data1.driveId) {
        data1.name = driveData.name;
      }
    }
    else {
      await this.getUserInfo();
      data1.canDelete = data1.capabilities.canRemoveChildren;
      data1.canShare = true;
      data1.canTrash = true;
    }

    const data2 = await this.apiRequest(
      `files?q="${this.folder}"+in+parents`
      + "+and+mimeType+!%3D+'application%2Fvnd.google-apps.shortcut'"
      + "+and+mimeType+!%3D+'application%2Fvnd.google-apps.folder'"
      + "+and+appProperties+has+%7B+key%3D'createdWithDdEfc'+and+value%3D'1'+%7D"
      + `&fields=files(id,webViewLink,permissionIds,size,name,mimeType,trashed)`
      + "&orderBy=name_natural&supportsAllDrives=true&includeItemsFromAllDrives=true"
    );

    return Object.assign(data2, data1);
  }

  async shareFile(fileId) {
    return await this.apiRequest(
      `files/${fileId}/permissions?supportsAllDrives=true`,
      {
        method: "POST",
        body: '{"role":"reader","type":"anyone"}',
        headers: {
          "Content-Type": "application/json"
        }
      }
    );
  }
  async trashFile(fileId) {
    return await this.apiRequest(
      `files/${fileId}?supportsAllDrives=true`,
      {
        method: "PATCH",
        body: '{"trashed":"true"}',
        headers: {
          "Content-Type": "application/json"
        }
      }
    );
  }
  async deleteFile(fileId) {
    return await this.apiRequest(
      `files/${fileId}?supportsAllDrives=true`,
      {method: "DELETE"}
    );
  }

  async getTokens(code, refresh) {
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
      this.accessToken = data.access_token;
      this.expires = new Date();
      this.expires.setSeconds(this.expires.getSeconds() + data.expires_in - 60);
      if(!refresh) {
        this.token = data.refresh_token;
      }
    }
    else {
      throw Error(await result.text());
    }
  };
  async renewToken() {
    if((new Date()) > this.expires) {
      await this.getTokens(this.token, true);
    }
  }
  // this doesn't work, refresh token gets revoked too...
  /* async forceRenewToken() {
    await Account.revokeToken(this.accessToken);
    await this.getTokens(this.token, true);
  } */

  async apiRequest(path, options) {
    await this.renewToken();

    const opt = options || {};
    opt.headers = opt.headers || {};
    opt.headers.Authorization = opt.headers.Authorization || `Bearer ${this.accessToken}`;
    opt.headers.Accept = opt.headers.Accept || "application/json";

    const result = await fetch(`https://www.googleapis.com/drive/v3/${path}`, opt);
    if(result.ok && opt.method === "DELETE") {
      return;
    }

    const text = await result.text();
    let responseData;
    try {
      responseData = JSON.parse(text);
    }
    catch(e) {
      throw Error(text);
    }

    if(typeof responseData.error !== "undefined") {
      throw Error(responseData.error.message);
    }
    return responseData;
  }

  async getUserInfo() {
    const data = await this.apiRequest(
      "about?fields=user%2FdisplayName%2Cuser%2FemailAddress%2C"
      + "storageQuota%2Flimit%2CstorageQuota%2Fusage"
    );
    this.usage = typeof data.storageQuota.usage === "undefined" ? 0 : Number(data.storageQuota.usage);
    this.limit = typeof data.storageQuota.limit === "undefined" ? Infinity : Number(data.storageQuota.limit);
    this.name = data.user.displayName;
    this.email = data.user.emailAddress;
  };

  static async revokeToken(token) {
    const result = await fetch(
      "https://oauth2.googleapis.com/revoke?token=" + encodeURIComponent(token),
      {method:"POST"}
    );

    const text = await result.text();
    let responseData;
    try {
      responseData = JSON.parse(text);
    }
    catch(e) {
      throw Error(text);
    }

    if(typeof responseData.error !== "undefined") {
      if(responseData.error === "invalid_token") {}
      else {
        throw Error(text);
      }
    }
  }
}

class FileList {
  constructor(target, name, toggleElements) {
    const hideElements = [`#collapse_files_${name}`];
    if(typeof toggleElements !== "undefined") {
      hideElements.push(toggleElements);
    }
    target.html($("#templates .file_list").html());
    this.self = target;
    this.name = name;
    this.self
      .find("h4").attr("data-target", hideElements.join(",")).end()
      .find(".collapse").attr("id", `collapse_files_${name}`).end()
      .find("thead")
        .find("label").attr("for", `check_all_${name}`).end()
        .find("input[type=checkbox]").attr("id", `check_all_${name}`).change(event => {
          this.getCheckboxes().prop("checked", event.target.checked);
        });
    this.clear();
  }

  clearCheckAll() {
    this.self.find("thead input[type=checkbox]").prop("checked", false);
  }

  clear() {
    this.count = 0;
    this.size = 0;
    this.files = {};
    this.self.find(".file_row").remove();
    this.clearCheckAll();
  }

  get count() {
    return this._count;
  }
  set count(value) {
    this._count = value;
    this.self.find(".details_container .files_count").text(value);
    if(value === 0) {
      this.self.find("table").hide();
    }
    // sanity check
    else if(value > 0) {
      this.self.find("table").show();
    }
  }

  get size() {
    return this._size;
  }
  set size(value) {
    this._size = value;
    this.self.find(".details_container .files_size").text(formatSize(value));
  }

  get title() {
    return this._title;
  }
  set title(value) {
    this._title = value;
    this.self.find(".title_container h4").text(value);
  }

  getCheckboxes() {
    return this.self.find(".file_row input[type=checkbox]");
  }
  getCheckedCheckboxes() {
    return this.getCheckboxes().filter(":checked");
  }

  getFiles(checkboxes) {
    const files = [];
    checkboxes.each((i, element) => {
      files.push(this.files[$(element).data("id")].data);
    });
    return files;
  }

  uncheckFiles(ids) {
    for(const id of ids) {
      this.files[id].element.find("input[type=checkbox]").prop("checked", false);
    }
    this.clearCheckAll();
  }

  addButton(buttonType, buttonName, callback, buttonClasses) {
    const buttonContainer = $("#templates .file_button").clone();
    const button = buttonContainer.find("button").text(buttonName);

    if(typeof buttonClasses !== "undefined") {
      for(const buttonClass of buttonClasses) {
        button.addClass(buttonClass);
      }
    }

    if(buttonType === "title") {
      this.self.find(".title_container").append(buttonContainer);
      button.click(event => {
        event.preventDefault();
        callback(this.getFiles(this.getCheckboxes()), event);
      });
    }
    else {
      this.self.find(".details_container").append(buttonContainer);
      button.click(event => {
        event.preventDefault();
        callback(this.getFiles(this.getCheckedCheckboxes()), event);
      });
    }
  }

  addFile(file) {
    // ignore folders and shortcuts
    if(IGNORED_MIMETYPE.has(file.mimeType)) {
      return;
    }
    const fileId = file.id;
    // ignore duplicates (only for encrypted folders, they don't return real IDs)
    if(typeof this.files[fileId] !== "undefined") {
      return;
    }
    
    const size = Number(file.size);
    const fileRow = $("#templates .file_row").clone()
      .find("input[type=checkbox]").attr("id", fileId).data("id", fileId).end()
      .find(".filename").attr("for", fileId).text(`${file.name} `).end()
      .find(".filesize").text(formatSize(size)).end();

    if(typeof file.webViewLink !== "undefined") {
      fileRow.find(".filename").append(
        $("<a>Download</a>").attr("href", file.webViewLink)
      );
    }

    this.files[fileId] = {
      data: file,
      element: fileRow
    };
    this.count += 1;
    this.size += size;

    this.self.find(".files").append(fileRow);
  }
  removeFile(file) {
    try {
      const id = getFileId(file);
      this.files[id].element.remove();
      delete this.files[id];
    }
    catch(e) {}
  }
}

function getFileId(file) {
  return (
      typeof file.id !== "undefined"
      ? file.id
      : [file.originalFilename, file.size, file.md5Checksum].join("*")
    );
}

const SIZES = ['B', 'KB', 'MB', 'GB', 'TB'];
function formatSize(sizeInBytes) {
  if(sizeInBytes === 0) {
    return "0B";
  }

  const index = Math.min(Math.floor(Math.log2(sizeInBytes) / 10), 4);
  const size = sizeInBytes / Math.pow(1024, index);
  return `${Number(size.toFixed(2))}${SIZES[index]}`;
}

function saveAsFile(filename, content) {
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
}

function keyCharAt(key, i) {
  return key.charCodeAt(i % key.length);
}
function xor(data, key) {
  const xored = new Uint8Array(data.length);
  for(let i=0; i<data.length; ++i){
    xored[i] = data[i] ^ keyCharAt(key, i);
  }
  return xored;
}
function xor_encrypt(data, key) {
  const enc = new TextEncoder();
  return b64.bytesToBase64(xor(enc.encode(data), key));
}
function xor_decrypt(data, key) {
  const dec = new TextDecoder();
  return dec.decode(xor(b64.base64ToBytes(data), key));
}

function getX(xName) {
  const xText = localStorage.getItem(xName);
  let x = {};
  if(xText !== null) {
    try {
      x = JSON.parse(xor_decrypt(xText, key));
    }
    catch(e) {}
  }
  return x;
}
function setX(xName, x) {
  localStorage.setItem(xName, xor_encrypt(JSON.stringify(x), key));
}

function getAccounts() {
  return getX("accounts");
}
function setAccounts(accounts) {
  setX("accounts", accounts);
}

function getServerCache() {
  return getX("serverCache");
}
function setServerCache(serverCache) {
  setX("serverCache", serverCache);
}

const modal = $("#error_modal");
function showModal(modalTitle, modalBody, class_, large) {
  if(large === true) {
    modal.find(".modal-dialog").addClass("modal-lg");
  }
  else {
    modal.find(".modal-dialog").removeClass("modal-lg");
  }
  modal.find(".modal-title").text(modalTitle)
    .parent()
    .removeClass("alert-danger alert-success alert-primary")
    .addClass(class_);
  modal.find(".modal-body").html(modalBody);
  modal.data('bs.modal', null).modal();
}
function showError(errorMessage, large) {
  showModal("Error", errorMessage, "alert-danger", large);
}
function showSuccess(successTitle, successBody){
  showModal(successTitle, successBody, "alert-success");
}

const loadingModal = $("#loading_modal");
function showLoading() {
  loadingModal.unbind("shown.bs.modal").on("hidden.bs.modal", () => {
    loadingModal.unbind("hidden.bs.modal").modal("show");
  }).modal("show");
}
function hideLoading() {
  loadingModal.unbind("hidden.bs.modal").on("shown.bs.modal", () => {
    loadingModal.unbind("shown.bs.modal").modal("hide");
  }).modal("hide");
}

function getAccountType(element) {
  const accType = $(element).closest("[data-account-type]").data("account-type");
  if(accType !== "main" && accType !== "dummy") {
    throw Error("Unknown account type");
  }
  return accType;
}

function listSavedAccounts() {
  const accs = getAccounts();
  const accRowTemplate = $("#templates .account_row");
  const accountListElement = $("#account_list");
  const table = accountListElement.find("tbody");
  const filterOut = [];
  for(const acc of Object.values(accounts)) {
    filterOut.push(acc.email);
  }

  let empty = true;
  for(const email of Object.keys(accs)) {
    if(filterOut.includes(email)) {
      continue;
    }

    const details = accs[email];
    const name = email !== "unknown" ? details.name : "unknown";
    const accRow = accRowTemplate.clone();

    accRow
      .data("email", email)
      .data("token", details.token)
      .find("td:first-child")
        .html(`<b>${name}</b> (${email})`);
    table.append(accRow);
    empty = false;
  }

  if(!empty) {
    accountListElement.show();
  }
}

function updateUserInfo() {
  for(const accountType of Object.keys(accounts)) {
    const acc = accounts[accountType];
    const free = acc.free;
    $(`[data-account-type="${accountType}"]`)
      .find(".user_name").html(`<b>${acc.name}</b> (${acc.email})`).end()
      .find(".free_space").html(`Free: <b>${free === Infinity ? "unlimited" : formatSize(free)}</b>`);
  }
}

async function logIn(accountType, code, oldEmail) {
  const accs = getAccounts();
  const refresh = typeof oldEmail !== "undefined";
  let account;

  showLoading();
  try {
    account = await Account.authenticate(code, refresh);
  }
  catch(e) {
    hideLoading();
    showError(e.message);
    return;
  }
  hideLoading();

  accounts[accountType] = account;

  // this shouldn't happen, can you even change email? but just in case...
  if(refresh) {
    const acc = accs[oldEmail];
    account.dummy = acc.dummy || false;
    account.folder = acc.folder || "root";
    if(account.email !== oldEmail) {
      delete accs[oldEmail];
    }
  }
  // if someone adds a new acc that's already on the list
  else {
    account.dummy = false;
    account.folder = "root";
    const acc = accs[account.email];
    if(typeof acc !== "undefined" && acc.token !== account.token) {
      Account.revokeToken(acc.token);
    }
  }
  accs[account.email] = Object.assign(accs[account.email] || {}, {
    name: account.name,
    token: account.token,
    dummy: account.dummy,
    folder: account.folder
  });
  setAccounts(accs);

  updateUserInfo();

  $("#account_selection").modal("hide");
  $(`[data-account-type="${accountType}"]`)
    .find(".select_acc").hide().end()
    .find(".acc_info").show();
  if(accountType === "main") {
    // copying with using dummy acc not implemented yet
    if(true) {
      showFiles();
    } else
    // hide buttons when selecting dummy acc or switching from normal to dummy acc
    if(account.dummy) {
      $('[data-account-type="dummy"] .select_acc').hide();
      showFiles();
    }
    // show buttons when selecting normal acc or switching from dummy to normal acc
    else if(typeof accounts.dummy === "undefined") {
      $('[data-account-type="dummy"] .select_acc').show();
    }
    else {
      showFiles();
    }
  }
  else {
    // always use "root" folder on dummy accounts
    account.folder = "root";
    showFiles();
  }
}

async function logOut(rowElem) {
  rowElem.addClass("loading");
  try {
    await Account.revokeToken(rowElem.data("token"));
  }
  catch(e) {
    rowElem.removeClass("loading");
    showError(e.message);
    return;
  }
  rowElem.removeClass("loading");
  const accs = getAccounts();
  delete accs[rowElem.data("email")];
  setAccounts(accs);

  $("#account_list")
    .hide()
    .find(".account_row")
      .remove();
  listSavedAccounts();
}

async function showFiles() {
  await reloadFolder();
  $("#my_files").show();
  $("#server_card").show();
}

async function reloadFolder() {
  let data;
  showLoading();
  try {
    data = await accounts.main.getMyFolder();
  }
  catch(e) {
    data = {
      name: "ERROR",
      canShare: false,
      canTrash: false,
      canDelete: false,
      error: e
    }
  }
  myFiles.clear();
  myFiles.title = data.name;
  myFiles.self
    .find(".share_button").prop("disabled", !data.canShare).end()
    .find(".trash_button").prop("disabled", !data.canTrash).end()
    .find(".delete_button").prop("disabled", !data.canDelete);
  if(data.canDelete) {
    myFiles.self.find(".trash_button").parent().hide();
    myFiles.self.find(".delete_button").parent().show();
  }
  else {
    myFiles.self.find(".trash_button").parent().show();
    myFiles.self.find(".delete_button").parent().hide();
  }

  if(typeof data.error !== "undefined") {
    hideLoading();
    showError(data.error.message);
    return;
  }

  updateUserInfo();
  for(const file of data.files) {
    if(!file.trashed) {
      myFiles.addFile(file);
    }
  }
  hideLoading();
}

function markAsDummy() {
  accounts.main.dummy = true;
  $('[data-account-type="dummy"] .select_acc').hide();
  const accs = getAccounts();
  accs[accounts.main.email].dummy = true;
  setAccounts(accs);
  showFiles();
}

function onAccountListClick(event) {
  const clickedElement = $(event.target);
  const accountType = getAccountType(event.target);

  // select account
  if(clickedElement.is("td:first-child")) {
    logIn(accountType, clickedElement.parent().data("token"), clickedElement.parent().data("email"));
  }
  // remove account
  else if(clickedElement.is(".remove-acc")) {
    event.preventDefault();
    logOut(clickedElement.closest("tr"));
  }
}

function onGetAuth(event) {
  event.preventDefault();
  const params = new URLSearchParams({
    "state": new URLSearchParams({
      "from": "gd-efc"
    }),
    "client_id": u,
    "redirect_uri": r,
    "response_type": "code",
    "access_type": "offline",
    "approval_prompt": "auto",
    "scope": "https://www.googleapis.com/auth/drive"
  });
  window.open(`https://accounts.google.com/o/oauth2/auth?${params.toString()}`);
}

function onAuthContinue(event) {
  event.preventDefault();
  const accountType = getAccountType(event.target);
  const code = $("#auth_input").val();
  logIn(accountType, code);
  $("#auth_input").val("");
}

async function onDestinationSet(event) {
  event.preventDefault();
  const url = $("#destination_input").val().trim();

  let id;
  if(url === "" || url === "root") {
    id = "root";
  }
  else {
    const m = url.match(/^https:\/\/drive\.google\.com\/(?:open\?id=|drive\/.*?folders\/)([0-9a-zA-Z\-_]+)/);
    if(m === null) {
      showError("Bad URL");
      return;
    }
    id = m[1];
  }

  showLoading();
  let data;
  try {
    data = await accounts.main.apiRequest(
      `files/${id}?supportsAllDrives=true`
      + "&fields=capabilities/canAddChildren");
    if(!data.capabilities.canAddChildren) {
      throw Error("Not a folder or can't create new files there.");
    }
  }
  catch(e) {
    hideLoading();
    showError(e.message);
    return;
  }
  hideLoading();

  const accs = getAccounts();
  accs[accounts.main.email].folder = id;
  setAccounts(accs);
  accounts.main.folder = id;

  $("#destination_selection").modal("hide");
  $("#destination_input").val("");

  reloadFolder();
}

async function onShare(files) {
  showLoading();
  const links = [];
  try {
    for(const file of files) {
      links.push(file.webViewLink);
      if(file.permissionIds.includes("anyoneWithLink")) {
        continue;
      }
      await accounts.main.shareFile(file.id);
      file.permissionIds.push("anyoneWithLink");
    }
    hideLoading();
  }
  catch(e) {
    hideLoading();
    showError(e.message);
    return;
  }
  $("#share_links").modal("show").find("textarea").val(links.join("\n"));
}
async function onTrashOrDelete(files, action) {
  showLoading();
  try {
    for(const file of files) {
      await accounts.main[action](file.id);
      myFiles.removeFile(file);
    }
  }
  catch(e) {
    hideLoading();
    showError(e.message);
  }
  reloadFolder();
}
async function onTrash(files) {
  return onTrashOrDelete(files, "trashFile");
}
async function onDelete(files) {
  return onTrashOrDelete(files, "deleteFile");
}

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
function formatServer(type_, args) {
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
}

class FolderManager {
  constructor() {
    this.initialized = false;
    this.encryptedIdOrUrl = null;
    this.idType = null;
    this.id = null;
    this.servers = null;
    this.lists = null;
    this.options = null;
    this.knownGoodServer = null;
  }

  init(encryptedIdOrUrl) {
    this.initialized = false;
    this.encryptedIdOrUrl = encryptedIdOrUrl;

    const m = encryptedIdOrUrl.match(/^https:\/\/drive\.google\.com\/(?:folderview\?id=|open\?id=|drive\/(?:u\/\d+\/)?folders\/|file\/(?:u\/\d+\/)?d\/)([0-9a-zA-Z\-_]+)/);
    if(m !== null) {
      this.idType = "normal";
      this.id = m[1];
    }
    else {
      this.idType = "encrypted";
      const encryptedParts = encryptedIdOrUrl.split(".");

      if(encryptedParts.length !== 2) {
        throw Error("Invalid encrypted folder ID.");
      }

      this.decodeDecryptServers(encryptedParts[0]);
      this.id = encryptedParts[1];

      const serverCache = getServerCache();
      for(const listUrl of this.lists) {
        if(typeof serverCache[listUrl] !== "undefined") {
          for(const serverUrl of serverCache[listUrl]) {
            this.servers.add(serverUrl);
          }
        }
      }
    }

    this.initialized = true;
  }

  decodeDecryptServers(serversAndOptions) {
    this.servers = new Set();
    this.lists = new Set();

    for(const server of atob(serversAndOptions).split(";")) {
      let type_, url;
      try {
        [, type_, url] = server.match(/^(.):(.+)$/);
      }
      catch(e) {
        type_ = "s";
        url = server;
      }

      if(type_ === "!") {
        this.parseOptions(url);
      }
      else {
        try {
          url = formatServer(type_, url.split("<"));
        }
        catch(e) {
          console.warn(e);
          continue;
        }

        if(BLACKLIST.has(server)) {
          continue;
        }

        if(LIST_TYPES.has(type_)) {
          this.lists.add(url);
        }
        else {
          this.servers.add(url);
        }
      }
    }
  }

  parseOptions(optionsString) {
    this.options = {};
    for(const option of optionsString.split("<")) {
      const optionParts = option.split(":");
      const optionName = optionParts.shift();
      if(optionParts.length === 0) {
        this.options[optionName] = true;
      }
      else if(optionParts.length === 1) {
        this.options[optionName] = optionParts[0];
      }
      else {
        this.options[optionName] = optionParts;
      }
    }
  }

  isInitialized() {
    if(!this.initialized) {
      throw Error("Folder manager not initialized.");
    }
  }

  async getServerList(url) {
    const servers = new Set();
    let data = "";
    try {
      data = await (await fetch(url)).text();
    }
    catch(e) {
      console.warn(url, e);
      try {
        data = await showPrompt("Open server list", `Open <a href="${url}">${url}</a> and paste the response below:`);
      }
      // cancelled, ignore
      catch(e) {}
    }

    for(const [, server] of data.matchAll(/^\s*(https?:\/\/.+?)\/?\s*$/gm)) {
      if(!BLACKLIST.has(server)) {
        this.servers.add(server);
        servers.add(server);
      }
    }

    if(servers.size > 0) {
      const serverCache = getServerCache();
      serverCache[url] = Array.from(servers);
      setServerCache(serverCache);
    }
  }

  async * getDecryptionServer() {
    const tested = new Set();

    // can be null but this.servers won't have null anyway
    if(this.servers.has(this.knownGoodServer)) {
      yield this.knownGoodServer;
      tested.add(this.knownGoodServer);
    }

    const yieldUntestedOnly = function* (serversSet) {
      const servers = Array.from(serversSet);

      while(servers.length > 0) {
        const index = Math.floor(Math.random() * servers.length);
        const server = servers.splice(index, 1)[0];

        if(!tested.has(server)) {
          yield server;
          tested.add(server);
        }
      }
    }

    yield* yieldUntestedOnly(this.servers);

    for(const listUrl of this.lists) {
      await this.getServerList(listUrl);
      yield* yieldUntestedOnly(this.servers);
    }

    let errorMessage = "<p>No working decryption server found.</p>";
    if(document.location.protocol === "https:" && Array.from(this.servers).some(x => x.startsWith("http:"))) {
      errorMessage += MIXED_CONTENT;
    }

    throw Error(errorMessage);
  }

  async getInfo() {
    this.isInitialized();

    if(this.idType === "normal") {
      return accounts.main.getFolder(this.id);
    }
    else {
      // return cached response if found
      const cachedResponse = sessionStorage.getItem(this.encryptedIdOrUrl);
      if(cachedResponse !== null) {
        return JSON.parse(cachedResponse);
      }

      const acc = typeof accounts.dummy === "undefined" ? accounts.main : accounts.dummy;

      for await(const server of this.getDecryptionServer()) {
        let info;
        try {
          info = await acc.serverRequest(server, this.id);
        }
        catch(e) {
          if(e instanceof ServerError) {
            throw e;
          }
          console.warn(server, e);
          continue;
        }

        // save response to cache
        sessionStorage.setItem(this.encryptedIdOrUrl, JSON.stringify(info));
        // set known good server, this will be used first in the next call
        this.knownGoodServer = server;
        return info;
      }
    }
  }

  async cloneFiles(files) {
    this.isInitialized();

    if(this.idType === "normal") {
      const result = [];
      for(const file of files) {
        const newFile = await accounts.main.cloneFile(file.id);
        result.push({
          id: file.id,
          data: newFile
        });
        myFiles.addFile(newFile);
      }
      return result;
    }
    else {
      if(typeof accounts.dummy !== "undefined") {
        throw Error("Copying through the dummy acc not implemented yet");
      }
      const acc = typeof accounts.dummy === "undefined" ? accounts.main : accounts.dummy;

      const ids = files.map(x => x.id);
      for await(const server of this.getDecryptionServer()) {
        let result;
        try {
          result = await acc.serverRequest(server, this.id, ids);
        }
        catch(e) {
          if(e instanceof ServerError) {
            throw e;
          }
          console.warn(server, e);
          continue;
        }

        // set known good server, this will be used first in the next call
        this.knownGoodServer = server;
        return result;
      }
    }
  }

}

async function onFolderLoad(event) {
  event.preventDefault();

  $("#server_files").hide();
  serverFiles.clear();

  showLoading();
  let info;
  try {
    folderManager.init($("#folder_input").val());
    info = await folderManager.getInfo();
  }
  catch(e) {
    hideLoading();
    showError(e.message, true);
    return;
  }
  hideLoading();

  serverFiles.clear();
  serverFiles.title = info.name;
  for(const file of info.files) {
    serverFiles.addFile(file);
  }

  $("#server_files").show();
}
function onMd5Download(files) {
  const lines = [];
  for(const file of files) {
    lines.push(`${file.md5Checksum} *${file.name}`);
  }
  lines.push("");

  saveAsFile("hashsums.md5", lines.join("\n"));
}
async function onCopy(files) {
  if(files.length === 0) {
    showError("No files selected.");
    return;
  }

  const filteredFiles = [];
  const free = accounts.main.free;
  let totalSize = 0;
  for(const file of files) {
    const size = Number(file.size);
    if(totalSize + size < free) {
      totalSize += size;
      filteredFiles.push(file);
    }
  }

  if(filteredFiles.length === 0) {
    showError("No space to copy any files.");
    return;
  }

  showLoading();
  let result;
  try {
    result = await folderManager.cloneFiles(filteredFiles);
  }
  catch(e) {
    hideLoading();
    showError(e.message, true);
    return;
  }
  hideLoading();
  const copiedIds = [];
  for(const item of result) {
    if(typeof item.data.error === "undefined") {
      copiedIds.push(item.id);
    }
  }
  serverFiles.uncheckFiles(copiedIds);

  if(files.length !== copiedIds.length) {
    showError("Some files weren't copied.");
  }

  reloadFolder();
}

function showPrompt(title, body) {
  return new Promise((resolve, reject) => {
    $("#modal_prompt")
      .data("resolve", resolve)
      .data("reject", reject)
      .find(".modal-title").text(title).end()
      .find(".prompt_body").html(body).end()
      .modal("show");
  });
}
$("#modal_prompt")
  .on("show.bs.modal", event => {
    $(event.target).find("textarea").val("");
  })
  .on("hidden.bs.modal", event => {
    const reject = $(event.target).data("reject");
    if(typeof reject !== "undefined") {
      reject(Error("Prompt cancelled"));
    }
  })
  .find("button.btn").click(event => {
    const modal = $("#modal_prompt");
    const resolve = modal.data("resolve");
    if(typeof resolve !== "undefined") {
      resolve(modal.find("textarea").val());
    }
    modal
      .removeData("resolve")
      .removeData("reject")
      .modal("hide");
  });

$("#mark_as_dummy").click(markAsDummy);
$("#account_list").click(onAccountListClick);
// on open/close account selection modal
$("#account_selection")
  .on("show.bs.modal", event => {
    const accountType = getAccountType(event.relatedTarget);
    $(event.target).data("account-type", accountType)
    listSavedAccounts();
  })
  .on("hidden.bs.modal", event => {
    $(event.target)
      .removeData("account-type")
      .find("#account_list")
        .hide()
        .find(".account_row")
          .remove();
  });
$("#get_auth").click(onGetAuth);
$("#auth_continue").click(onAuthContinue);
$("#destination_continue").click(onDestinationSet);
$("#folder_load").click(onFolderLoad);

const u = xor_decrypt("BFRoR09cF2ZFBQ1sXBhJKUVgXyMOBD0XIic1QQU+WRU1Vx9mJTkV", key);
const p = xor_decrypt("blAARhoJFy8WZH06Qy9WNhsIAS1WOSk4", key);
const r = "urn:ietf:wg:oauth:2.0:oob";
const myFiles = new FileList($("#my_files .file_list"), "my", ".reload_button");
myFiles.addButton("title", "Reload", reloadFolder, ["reload_button", "collapse", "show"]);
myFiles.addButton("title", "Select", () => $("#destination_selection").modal("show"));
myFiles.addButton("details", "Share", onShare, ["share_button"]);
myFiles.addButton("details", "Trash", onTrash, ["trash_button"]);
myFiles.addButton("details", "Delete", onDelete, ["delete_button"]);
const serverFiles = new FileList($("#server_files .file_list"), "server");
serverFiles.addButton("title", ".MD5", onMd5Download);
serverFiles.addButton("details", "Copy", onCopy);

const folderManager = new FolderManager();

// show instructions first time
if(localStorage.getItem("instructionsShown") !== "true") {
  $("#instructions_modal").on("hidden.bs.modal", event => {
    $(event.target).unbind("hidden.bs.modal").data('bs.modal', null);
  }).modal({
    keyboard: false,
    backdrop: "static"
  });
  localStorage.setItem("instructionsShown", "true");
}

// convert old token format to new one
{
  const refToken = localStorage.getItem("refresh_token");
  if(refToken !== null) {
    const accounts = getAccounts();
    accounts["unknown"] = {
      token: xor_decrypt(refToken, key)
    };
    setAccounts(accounts);
    localStorage.removeItem("refresh_token");
  }
}

// modal stacking
$(document).on('show.bs.modal', '.modal', function () {
  var zIndex = 1040 + (10 * $('.modal:visible').length);
  $(this).css('z-index', zIndex);
  setTimeout(function() {
    $('.modal-backdrop').not('.modal-stack').css('z-index', zIndex - 1).addClass('modal-stack');
  }, 0);
});

// })();
