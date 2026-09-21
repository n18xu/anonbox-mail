-- Labels for anonymous addresses. The browser encrypts them with the account's
-- own public key, so the server only ever stores ciphertext.
ALTER TABLE aliases ADD COLUMN label_encrypted TEXT;
