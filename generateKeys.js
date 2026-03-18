const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
});

fs.writeFileSync(path.join(__dirname, 'private.key'), privateKey);
fs.writeFileSync(path.join(__dirname, 'public.key'), publicKey);

console.log('✅ Đã tạo private.key và public.key thành công!');