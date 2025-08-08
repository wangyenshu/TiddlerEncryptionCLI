// TiddlerEncryption.js
const fs = require('fs');
const crypto = require('crypto');
const readline = require('readline');

// --- Helper Functions from Original Plugin ---
// These are the core TEA encryption/decryption functions and helpers.

function strToLongs(s) {
    const l = new Array(Math.ceil(s.length / 4));
    for (let i = 0; i < l.length; i++) {
        l[i] = s.charCodeAt(i * 4) + (s.charCodeAt(i * 4 + 1) << 8) +
            (s.charCodeAt(i * 4 + 2) << 16) + (s.charCodeAt(i * 4 + 3) << 24);
    }
    return l;
}

function longsToStr(l) {
    const a = new Array(l.length);
    for (let i = 0; i < l.length; i++) {
        a[i] = String.fromCharCode(l[i] & 0xFF, l[i] >>> 8 & 0xFF,
            l[i] >>> 16 & 0xFF, l[i] >>> 24 & 0xFF);
    }
    return a.join('');
}

function escCtrlCh(str) {
    return str.replace(/[\0\t\n\v\f\r\xa0'"!]/g, c => `!${c.charCodeAt(0)}!`);
}

function unescCtrlCh(str) {
    return str.replace(/!\d\d?\d?!/g, c => String.fromCharCode(c.slice(1, -1)));
}

function TEAencrypt(plaintext, password) {
    if (plaintext.length === 0) return '';
    const asciitext = encodeURIComponent(plaintext).replace(/%20/g, ' ');
    const v = strToLongs(asciitext);
    if (v.length <= 1) v[1] = 0;
    const k = strToLongs(password.slice(0, 16));
    const n = v.length;
    let z = v[n - 1], y = v[0], delta = 0x9E3779B9;
    let mx, e, q = Math.floor(6 + 52 / n), sum = 0;
    while (q-- > 0) {
        sum += delta;
        e = sum >>> 2 & 3;
        for (let p = 0; p < n; p++) {
            y = v[(p + 1) % n];
            mx = (z >>> 5 ^ y << 2) + (y >>> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z);
            z = v[p] += mx;
        }
    }
    const ciphertext = longsToStr(v);
    return escCtrlCh(ciphertext);
}

function TEAdecrypt(ciphertext, password) {
    if (ciphertext.length === 0) return '';
    const v = strToLongs(unescCtrlCh(ciphertext));
    const k = strToLongs(password.slice(0, 16));
    const n = v.length;
    let z = v[n - 1], y = v[0], delta = 0x9E3779B9;
    let mx, e, q = Math.floor(6 + 52 / n), sum = q * delta;
    while (sum !== 0) {
        e = sum >>> 2 & 3;
        for (let p = n - 1; p >= 0; p--) {
            z = v[p > 0 ? p - 1 : n - 1];
            mx = (z >>> 5 ^ y << 2) + (y >>> 3 ^ z << 4) ^ (sum ^ y) + (k[p & 3 ^ e] ^ z);
            y = v[p] -= mx;
        }
        sum -= delta;
    }
    let plaintext = longsToStr(v);
    plaintext = plaintext.replace(/\0+$/, '');
    return decodeURIComponent(plaintext);
}

function stringToHext(theString) {
    let theResult = "";
    for (let i = 0; i < theString.length; i++) {
        const theHex = theString.charCodeAt(i).toString(16);
        theResult += theHex.length < 2 ? `0${theHex}` : theHex;
    }
    // Add newlines for readability, just like the original plugin
    let formattedResult = '';
    for (let i = 0; i < theResult.length; i += 64) {
        formattedResult += theResult.substring(i, i + 64);
        if (i + 64 < theResult.length) {
            formattedResult += '\n';
        }
    }
    return formattedResult;
}

function hexToString(theString) {
    let theResult = "";
    // Remove all whitespace and newlines from the hex string
    const sanitizedHex = theString.replace(/\s+/g, '');
    for (let i = 0; i < sanitizedHex.length; i += 2) {
        theResult += String.fromCharCode(parseInt(sanitizedHex.substr(i, 2), 16));
    }
    return theResult;
}

function hexSha1Str(str) {
    const hash = crypto.createHash('sha1');
    hash.update(str);
    return hash.digest('hex').toUpperCase();
}

// --- CLI Logic ---

async function promptPassword(prompt) {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
    });
    return new Promise(resolve => {
        rl.question(prompt, { hideEchoBack: true }, password => {
            rl.close();
            resolve(password);
        });
    });
}

async function runCli() {
    const args = process.argv.slice(2);
    const [action, filePath, promptString] = args;

    if (!action || !filePath || !promptString) {
        console.error('❌ Usage: node TiddlerEncryption.js [encrypt|decrypt] <file_path> <prompt_string>');
        process.exit(1);
    }

    try {
        const fileContent = fs.readFileSync(filePath, 'utf8');
        
        const tiddlerRegex = new RegExp(`(<div[^>]*tags=")([^"]+)(".*?>[\\s\\S]*?<pre>)([\\s\\S]*?)(<\\/pre>[\\s\\S]*<\\/div>)`);
        const match = fileContent.match(tiddlerRegex);

        if (!match) {
            throw new Error('Tiddler file is not in the expected format (missing <div>, tags, or <pre>).');
        }

        const [_, preTags, tagsString, postTags, content, endDiv] = match;
        const tagsArray = tagsString.split(' ').filter(tag => tag.length > 0);

        const password = await promptPassword(`Enter password for '${promptString}': `);

        let newContentText;
        let newTagsArray;
        let originalContent;

        if (action === 'encrypt') {
            const encryptTag = `Encrypt(${promptString})`;
            const decryptTag = `Decrypt(${promptString})`;

            if (!tagsArray.includes(encryptTag)) {
                throw new Error(`Tiddler does not have the tag '${encryptTag}'.`);
            }
            
            originalContent = content.trim();

            const decryptedSHA1 = hexSha1Str(originalContent);
            const encryptedText = TEAencrypt(originalContent, password);
            const encryptedHexText = stringToHext(encryptedText);
            newContentText = `Encrypted(${decryptedSHA1})\n${encryptedHexText}`;

            newTagsArray = tagsArray.map(tag => tag === encryptTag ? decryptTag : tag);
        } else if (action === 'decrypt') {
            const decryptTag = `Decrypt(${promptString})`;
            const encryptTag = `Encrypt(${promptString})`;

            if (!tagsArray.includes(decryptTag)) {
                throw new Error(`Tiddler does not have the tag '${decryptTag}'.`);
            }

            const contentMatch = content.trim().match(/^Encrypted\((.*?)\)\n([\s\S]*)/);
            if (!contentMatch) {
                throw new Error('Encrypted content is not in the expected format.');
            }

            const [_, checksum, encryptedHexText] = contentMatch;
            const encryptedText = hexToString(encryptedHexText);
            const decryptedText = TEAdecrypt(encryptedText, password);
            const thisDecryptedSHA1 = hexSha1Str(decryptedText);

            if (checksum !== thisDecryptedSHA1) {
                throw new Error('Checksum mismatch. Decryption failed or wrong password.');
            }

            newContentText = decryptedText;
            newTagsArray = tagsArray.map(tag => tag === decryptTag ? encryptTag : tag);
        } else {
            throw new Error('Invalid action. Use "encrypt" or "decrypt".');
        }

        const newTagsString = newTagsArray.join(' ');
        const newFileContent = `${preTags}${newTagsString}${postTags}${newContentText}${endDiv}`;

        fs.writeFileSync(filePath, newFileContent, 'utf8');
        console.log(`✅ Successfully ${action}ed file: ${filePath}`);
    } catch (err) {
        console.error('❌ An error occurred:', err.message);
        process.exit(1);
    }
}

// Run the CLI
runCli();
