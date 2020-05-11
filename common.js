// minified version of https://gist.github.com/enepomnyaschih/72c423f727d395eeaa09697058238727
(function(w){"use strict";var b64={},base64abc=["A","B","C","D","E","F","G","H","I","J","K","L","M","N","O","P","Q","R","S","T","U","V","W","X","Y","Z","a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q","r","s","t","u","v","w","x","y","z","0","1","2","3","4","5","6","7","8","9","+","/"],base64codes=[255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,62,255,255,255,63,52,53,54,55,56,57,58,59,60,61,255,255,255,0,255,255,255,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,255,255,255,255,255,255,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51];function getBase64Code(e){if(e>base64codes.length)throw new Error("Unable to parse base64 string.");var a=base64codes[e];if(255===a)throw new Error("Unable to parse base64 string.");return a}function bytesToBase64(e){var a,s="",t=e.length;for(a=2;a<t;a+=3)s+=base64abc[e[a-2]>>2],s+=base64abc[(3&e[a-2])<<4|e[a-1]>>4],s+=base64abc[(15&e[a-1])<<2|e[a]>>6],s+=base64abc[63&e[a]];return a===t+1&&(s+=base64abc[e[a-2]>>2],s+=base64abc[(3&e[a-2])<<4],s+="=="),a===t&&(s+=base64abc[e[a-2]>>2],s+=base64abc[(3&e[a-2])<<4|e[a-1]>>4],s+=base64abc[(15&e[a-1])<<2],s+="="),s}function base64ToBytes(e){if(e.length%4!=0)throw new Error("Unable to parse base64 string.");var a=e.indexOf("=");if(-1!==a&&a<e.length-2)throw new Error("Unable to parse base64 string.");for(var s,t=e.endsWith("==")?2:e.endsWith("=")?1:0,r=e.length,o=new Uint8Array(r/4*3),n=0,b=0;n<r;n+=4,b+=3)s=getBase64Code(e.charCodeAt(n))<<18|getBase64Code(e.charCodeAt(n+1))<<12|getBase64Code(e.charCodeAt(n+2))<<6|getBase64Code(e.charCodeAt(n+3)),o[b]=s>>16,o[b+1]=s>>8&255,o[b+2]=255&s;return o.subarray(0,o.length-t)}function base64encode(e){return bytesToBase64((arguments.length>1&&void 0!==arguments[1]?arguments[1]:new TextEncoder).encode(e))}function base64decode(e){return(arguments.length>1&&void 0!==arguments[1]?arguments[1]:new TextDecoder).decode(base64ToBytes(e))}b64.bytesToBase64=bytesToBase64;b64.base64ToBytes=base64ToBytes;b64.base64encode=base64encode;b64.base64decode=base64decode;w.b64=b64})(this);

async function encrypt(text, b64Key) {
  const key = await crypto.subtle.importKey(
    "raw",
    b64.base64ToBytes(b64Key),
    {name: "AES-GCM"},
    false,
    ["encrypt"]
  );
  const enc = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv
    },
    key,
    enc.encode(text)
  );

  const result = new Uint8Array(iv.length + ciphertext.byteLength);
  result.set(iv);
  result.set(new Uint8Array(ciphertext), iv.length);

  return b64.bytesToBase64(result);
}

async function decrypt(encryptedText, b64Key) {
  const key = await crypto.subtle.importKey(
    "raw",
    b64.base64ToBytes(b64Key),
    {name: "AES-GCM"},
    false,
    ["decrypt"]
  );
  const encryptedBytes = b64.base64ToBytes(encryptedText);
  const iv = encryptedBytes.slice(0, 12);
  const ciphertext = encryptedBytes.slice(12);

  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv
    },
    key,
    ciphertext
  );
  const dec = new TextDecoder();

  return dec.decode(decrypted);
}

async function generateKey() {
  const key = await crypto.subtle.generateKey(
    {
        name: "AES-GCM",
        length: 256,
    },
    true,
    ["encrypt"] // Chrome doesn't like when it's empty
  );
  const rawKey = await crypto.subtle.exportKey("raw", key);
  return b64.bytesToBase64(new Uint8Array(rawKey));
}