const createWalletButton = document.getElementById("createWallet");
const loadWalletButton = document.getElementById("loadWallet");
const walletOutput = document.getElementById("walletOutput");
const recipientInput = document.getElementById("recipient");
const amountInput = document.getElementById("amount");
const sendFundsButton = document.getElementById("sendFunds");
const transactionOutput = document.getElementById("transactionOutput");

// Gnosis Chain RPC URL
const GNOSIS_RPC_URL = "https://rpc.gnosischain.com";

// Generate and store a consistent user ID for WebAuthn
let userId = localStorage.getItem("walletUserId");
if (!userId) {
    userId = new Uint8Array(16);
    window.crypto.getRandomValues(userId);
    localStorage.setItem("walletUserId", JSON.stringify(Array.from(userId)));
} else {
    userId = new Uint8Array(JSON.parse(userId));
}

// Helper function to convert ArrayBuffer to a Hexadecimal String
function bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
}

/**
 * Registers a passkey using WebAuthn and derives the wallet deterministically.
 */
/**
 * Registers a passkey using WebAuthn and derives the wallet deterministically.
 */
async function registerPasskey() {
    try {
        const challenge = new Uint8Array(32);
        window.crypto.getRandomValues(challenge);

        const credential = await navigator.credentials.create({
            publicKey: {
                challenge: challenge,
                rp: { name: "Gnosis Wallet" },
                user: {
                    id: userId,
                    name: "user@example.com",
                    displayName: "Gnosis Wallet User"
                },
                pubKeyCredParams: [
                    { type: "public-key", alg: -7 },    // ES256
                    { type: "public-key", alg: -257 }   // RS256
                ],
                authenticatorSelection: {
                    userVerification: "required",
                    authenticatorAttachment: "platform" // Use device biometrics
                },
                timeout: 120000, // 2 minutes
            }
        });

        console.log("Credential Object:", credential);

        if (!credential || !credential.rawId || !credential.id) {
            console.error("Credential object is invalid:", credential);
            throw new Error("Credential is missing required properties (rawId or id).");
        }

        console.log("Credential ID (Base64):", credential.id);
        console.log("Credential RawID:", credential.rawId);

        // Convert rawId to hexadecimal
        const rawIdHex = bufferToHex(credential.rawId);
        console.log("Converted rawId (Hex):", rawIdHex);

        // Ensure ethers.js is loaded
        if (typeof ethers === "undefined") {
            throw new Error("Ethers.js is not loaded. Please include it in your HTML file.");
        }

        // Use ethers.keccak256 to hash the rawIdHex
        const hashedRawId = ethers.keccak256(ethers.toUtf8Bytes(rawIdHex));

        // Create a wallet using the hashed seed
        const wallet = new ethers.Wallet(hashedRawId);

        console.log("Passkey registered successfully!");
        console.log("Derived Wallet Address:", wallet.address);

        // Save credential ID for authentication
        localStorage.setItem("credentialId", JSON.stringify(Array.from(new Uint8Array(credential.rawId))));

        return wallet;
    } catch (error) {
        console.error("Error during WebAuthn registration:", error);
        alert(`Failed to register passkey: ${error.message}`);
        throw error;
    }
}

/**
 * Authenticates the user with WebAuthn and derives the wallet deterministically.
 */
/**
 * Authenticates the user with WebAuthn and derives the wallet deterministically.
 */
async function authenticateWallet() {
    try {
        const challenge = new Uint8Array(32);
        window.crypto.getRandomValues(challenge);

        // Retrieve the stored credential ID
        const credentialId = localStorage.getItem("credentialId");
        if (!credentialId) {
            throw new Error("No registered passkey found. Please register first.");
        }

        const assertion = await navigator.credentials.get({
            publicKey: {
                challenge: challenge,
                allowCredentials: [
                    {
                        type: "public-key",
                        id: new Uint8Array(JSON.parse(credentialId)), // Use stored credential ID
                    }
                ],
                userVerification: "required",
            }
        });

        console.log("Passkey authenticated successfully:", assertion);

        // Convert rawId to a hexadecimal string
        const rawIdHex = bufferToHex(assertion.rawId);
        console.log("Converted rawId (Hex):", rawIdHex);

        // Ensure ethers.js is loaded
        if (typeof ethers === "undefined") {
            throw new Error("Ethers.js is not loaded. Please include it in your HTML file.");
        }

        // Use ethers.keccak256 to hash the rawIdHex
        const hashedRawId = ethers.keccak256(ethers.toUtf8Bytes(rawIdHex));

        // Derive wallet from the hashed seed
        const wallet = new ethers.Wallet(hashedRawId);

        console.log("Derived Wallet Address:", wallet.address);
        return wallet;
    } catch (error) {
        console.error("Error during WebAuthn authentication:", error);
        alert(`Failed to authenticate wallet: ${error.message}`);
        throw error;
    }
}

// Create Wallet
createWalletButton.addEventListener("click", async () => {
    try {
        const wallet = await registerPasskey();

        walletOutput.value = `Wallet created and secured with passkey!\nAddress: ${wallet.address}`;
        console.log("Wallet Address:", wallet.address);
    } catch (error) {
        console.error("Error creating wallet:", error);
        alert("Failed to create wallet. Ensure your device supports WebAuthn.");
    }
});

// Load Wallet
loadWalletButton.addEventListener("click", async () => {
    try {
        const wallet = await authenticateWallet();

        walletOutput.value = `Wallet loaded successfully!\nAddress: ${wallet.address}`;
        console.log("Wallet Address:", wallet.address);
    } catch (error) {
        console.error("Error loading wallet:", error);
        alert("Failed to load wallet. Ensure you authenticate correctly.");
    }
});

// Send Funds
sendFundsButton.addEventListener("click", async () => {
    const recipient = recipientInput.value.trim();
    const amount = parseFloat(amountInput.value);

    if (!ethers.utils.isAddress(recipient)) {
        alert("Invalid recipient address!");
        return;
    }

    if (isNaN(amount) || amount <= 0) {
        alert("Invalid amount!");
        return;
    }

    try {
        const wallet = await authenticateWallet();
        const provider = new ethers.providers.JsonRpcProvider(GNOSIS_RPC_URL);
        const walletWithProvider = wallet.connect(provider);

        const tx = await walletWithProvider.sendTransaction({
            to: recipient,
            value: ethers.utils.parseEther(amount.toString())
        });

        transactionOutput.value = `Transaction sent!\nHash: ${tx.hash}`;
        console.log("Transaction:", tx);

        // Wait for transaction confirmation
        const receipt = await tx.wait();
        transactionOutput.value += `\nTransaction confirmed in block ${receipt.blockNumber}`;
    } catch (error) {
        console.error("Error sending funds:", error);
        alert("Failed to send funds. Check console for details.");
    }
});
