import { generateKeyPairSync } from "node:crypto";

const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });

const pubJwk = publicKey.export({ format: "jwk" });
const xBytes = Buffer.from(pubJwk.x, "base64url");
const yBytes = Buffer.from(pubJwk.y, "base64url");
const uncompressed = Buffer.concat([Buffer.from([0x04]), xBytes, yBytes]);
const publicKeyB64 = uncompressed.toString("base64url");

const privatePkcs8 = privateKey.export({ format: "der", type: "pkcs8" });
const privateKeyB64 = privatePkcs8.toString("base64");

console.log("VAPID_PUBLIC_KEY=" + publicKeyB64);
console.log("VAPID_PRIVATE_KEY=" + privateKeyB64);
