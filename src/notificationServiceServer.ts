
import { Application, Router, Context } from "https://deno.land/x/oak@v12.6.1/mod.ts";
import { setupDatabase } from "./notificationSenderPolicy.ts";
import * as secp from "https://deno.land/x/secp256k1@2.0.0/mod.ts";
import { sha256 } from 'npm:@noble/hashes@1.2.0/sha256';

const app = new Application();
const router = new Router();

const db = await setupDatabase();


// Define the endpoint for the client to send device tokens to
router.post("/user-info", async (ctx: Context) => {
    console.log("Received POST request to /user-info");
    const body = await ctx.request.body();
    const bodyValue = await body.value;
    console.log(bodyValue);
    const { deviceToken, pubkey, timestamp, signature } = bodyValue

    // Verify the ISO8601 timestamp is within 10 minutes of now
    const now = new Date();
    const tenMinutesAgo = new Date(now.getTime() - 10 * 60 * 1000);
    const tenMinutesFromNow = new Date(now.getTime() + 10 * 60 * 1000);
    const timestampDate = new Date(timestamp);

    if (timestampDate < tenMinutesAgo || timestampDate > tenMinutesFromNow) {
        ctx.response.status = 400;  // Bad request
        ctx.response.body = "Timestamp is not within 10 minutes of now";
        return;
    }

    const signedMessage = `${deviceToken}${timestamp}`;

    // Get the SHA256 hash of the signed message
    const signedMessageHash = sha256(signedMessage);

    console.log(`Signed message hash: ${Array.from(signedMessageHash).map(b => b.toString(16).padStart(2, '0')).join('')}`);

    // Signature is base64 encoded, so decode it to get the raw bytes, then 
    const signatureBytes = Uint8Array.from(atob(signature), c => c.charCodeAt(0))

    console.log(`Signature: ${Array.from(signatureBytes).map(b => b.toString(16).padStart(2, '0')).join('')}`);

    // pubkey is an ASCII string of hex digits (e.g the string literal "113f"), so convert it to raw bytes
    let pubkeyBytes: Uint8Array = pubkey.match(/[0-9a-f]{2}/gi)!.map((h: string) => parseInt(h, 16));

    // Add 0x02 prefix to pubkey
    pubkeyBytes = Uint8Array.from([0x02, ...pubkeyBytes]);

    console.log(`Pubkey: ${Array.from(pubkeyBytes).map(b => b.toString(16).padStart(2, '0')).join('')}`);

    console.log("Checking signature");

    // Verify the signature
    const signatureValid = secp.verify(
        signatureBytes,
        signedMessageHash,
        pubkeyBytes
    );

    console.log(`Is signature valid: ${signatureValid}`);

    if(!signatureValid) {
        ctx.response.status = 401;  // Unauthorized
        ctx.response.body = "Signature is invalid. Not authorized to save device token";
        return;
    }

    console.log(`Received device token ${deviceToken} for pubkey ${pubkey}`)
    await db.query('INSERT OR REPLACE INTO user_info (pubkey, device_tokens) VALUES (?, ?)', [pubkey, JSON.stringify([deviceToken])]);
    ctx.response.body = "User info saved successfully";
});

app.use(router.routes());
app.use(router.allowedMethods());

console.log("Server running on port 8000");

await app.listen({ port: 8000 });
