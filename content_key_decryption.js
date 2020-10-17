/*
This is where the magic happens
*/


var WidevineCrypto = {};

(function() {

// The public 2048-bit RSA key Widevine uses for Chrome devices in L3
WidevineCrypto.chromeRSAPublicKey = 
`-----BEGIN PUBLIC KEY-----
[redacted]
-----END PUBLIC KEY-----`;

// The private 2048-bit RSA key Widevine uses for authenticating Chrome devices in L3
// Extracted by applying some mathematical tricks to Araxan's white-box algorithm
WidevineCrypto.chromeRSAPrivateKey = 
`-----BEGIN PRIVATE KEY-----
[redacted]
-----END PRIVATE KEY-----`;

WidevineCrypto.initializeKeys = async function()
{
    // load the device RSA keys for various purposes
    this.publicKeyEncrypt =  await crypto.subtle.importKey('spki', PEM2Binary(this.chromeRSAPublicKey),   {name: 'RSA-OAEP', hash: { name: 'SHA-1' },}, true, ['encrypt']);
    this.publicKeyVerify =   await crypto.subtle.importKey('spki', PEM2Binary(this.chromeRSAPublicKey),   {name: 'RSA-PSS',  hash: { name: 'SHA-1' },}, true, ['verify']);
    this.privateKeyDecrypt = await crypto.subtle.importKey('pkcs8', PEM2Binary(this.chromeRSAPrivateKey), {name: 'RSA-OAEP', hash: { name: 'SHA-1' },}, true, ['decrypt']);

    var isRSAGood = await isRSAConsistent(this.publicKeyEncrypt, this.privateKeyDecrypt);
    if (!isRSAGood)
    {
        throw "Can't verify RSA keys consistency; This means the public key does not match the private key!";
    }

    this.keysInitialized = true;
}

WidevineCrypto.decryptContentKey = async function(licenseRequest, licenseResponse)
{
    licenseRequest = SignedMessage.read(new Pbf(licenseRequest));
    licenseResponse = SignedMessage.read(new Pbf(licenseResponse));

    if (licenseRequest.type != SignedMessage.MessageType.LICENSE_REQUEST.value) return;

    license = License.read(new Pbf(licenseResponse.msg));
    
    if (!this.keysInitialized) await this.initializeKeys();
    
    // make sure the signature in the license request validates under the private key
    var signatureVerified = await window.crypto.subtle.verify({name: "RSA-PSS", saltLength: 20,}, this.publicKeyVerify, 
                                                              licenseRequest.signature, licenseRequest.msg)
    if (!signatureVerified)
    {
        console.log("Can't verify license request signature; either the platform is wrong or the key has changed!");
        return null;
    }

    // decrypt the session key
    var sessionKey = await crypto.subtle.decrypt({name: "RSA-OAEP"}, this.privateKeyDecrypt, licenseResponse.session_key);

    // calculate context_enc
    var encoder = new TextEncoder();
    var keySize = 128;
    var context_enc = concatBuffers([[0x01], encoder.encode("ENCRYPTION"), [0x00], licenseRequest.msg, intToBuffer(keySize)]);

    // calculate encrypt_key using CMAC
    var encryptKey = wordToByteArray(
                    CryptoJS.CMAC(arrayToWordArray(new Uint8Array(sessionKey)), 
                                  arrayToWordArray(new Uint8Array(context_enc))).words);

    // iterate the keys we got to find those we want to decrypt (the content key(s))
    var contentKeys = []
    for (currentKey of license.key)
    {
        if (currentKey.type != License.KeyContainer.KeyType.CONTENT.value) continue;

        var keyId = currentKey.id;
        var keyData = currentKey.key.slice(0, 16); 
        var keyIv = currentKey.iv.slice(0, 16);

        // finally decrypt the content key
        var decryptedKey = wordToByteArray(
            CryptoJS.AES.decrypt({ ciphertext: arrayToWordArray(keyData) }, arrayToWordArray(encryptKey), { iv: arrayToWordArray(keyIv) }).words);

        contentKeys.push(decryptedKey);
        console.log("WidevineDecryptor: Found key: " + toHexString(decryptedKey) + " (KID=" + toHexString(keyId) + ")");
    }

    return contentKeys[0];
}

//
// Helper functions
//

async function isRSAConsistent(publicKey, privateKey)
{
    // See if the data is correctly decrypted after encryption
    var testData = new Uint8Array([0x41, 0x42, 0x43, 0x44]);
    var encryptedData = await crypto.subtle.encrypt({name: "RSA-OAEP"}, publicKey, testData);
    var testDecryptedData = await crypto.subtle.decrypt({name: "RSA-OAEP"}, privateKey, encryptedData);

    return areBuffersEqual(testData, testDecryptedData);
}

function areBuffersEqual(buf1, buf2)
{
    if (buf1.byteLength != buf2.byteLength) return false;
    var dv1 = new Int8Array(buf1);
    var dv2 = new Int8Array(buf2);
    for (var i = 0 ; i != buf1.byteLength ; i++)
    {
        if (dv1[i] != dv2[i]) return false;
    }
    return true;
}

function concatBuffers(arrays) 
{
    // Get the total length of all arrays.
    let length = 0;
    arrays.forEach(item => {
      length += item.length;
    });
    
    // Create a new array with total length and merge all source arrays.
    let mergedArray = new Uint8Array(length);
    let offset = 0;
    arrays.forEach(item => {
      mergedArray.set(new Uint8Array(item), offset);
      offset += item.length;
    }); 
    
    return mergedArray;
}

// CryptoJS format to byte array
function wordToByteArray(wordArray) 
{
    var byteArray = [], word, i, j;
    for (i = 0; i < wordArray.length; ++i) {
        word = wordArray[i];
        for (j = 3; j >= 0; --j) {
            byteArray.push((word >> 8 * j) & 0xFF);
        }
    }
    return byteArray;
}

// byte array to CryptoJS format
function arrayToWordArray(u8Array) 
{
	var words = [], i = 0, len = u8Array.length;

	while (i < len) {
		words.push(
			(u8Array[i++] << 24) |
			(u8Array[i++] << 16) |
			(u8Array[i++] << 8)  |
			(u8Array[i++])
		);
	}

	return {
		sigBytes: len,
		words: words
	};
}

const toHexString = bytes => bytes.reduce((str, byte) => str + byte.toString(16).padStart(2, '0'), '');

const intToBuffer = num => 
{
    let b = new ArrayBuffer(4);
    new DataView(b).setUint32(0, num);
    return Array.from(new Uint8Array(b));
}

function PEM2Binary(pem) 
{
    var encoded = '';
    var lines = pem.split('\n');
    for (var i = 0; i < lines.length; i++) {
        if (lines[i].indexOf('-----') < 0) {
            encoded += lines[i];
        }
    }
    var byteStr = atob(encoded);
    var bytes = new Uint8Array(byteStr.length);
    for (var i = 0; i < byteStr.length; i++) {
        bytes[i] = byteStr.charCodeAt(i);
    }
    return bytes.buffer;
}

}());
