const createWalletButton = document.getElementById("createWallet");
const loadWalletButton = document.getElementById("loadWallet");
const walletOutput = document.getElementById("walletOutput");
const recipientInput = document.getElementById("recipient");
const amountInput = document.getElementById("amount");
const sendFundsButton = document.getElementById("sendFunds");
const transactionOutput = document.getElementById("transactionOutput");
const walletBalanceDiv = document.getElementById("walletBalance");

// Gnosis Chain RPC URL
const GNOSIS_RPC_URL = "https://rpc.gnosis.gateway.fm";

// Helper function to convert ArrayBuffer to a Hexadecimal String
function bufferToHex(buffer) {
    return Array.from(new Uint8Array(buffer))
        .map(byte => byte.toString(16).padStart(2, '0'))
        .join('');
}

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
                    id: new Uint8Array(16), // Random user ID
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
            throw new Error("Credential is missing required properties (rawId or id).");
        }

        console.log("Credential ID (Base64):", credential.id);
        console.log("Credential RawID:", credential.rawId);

        // Convert rawId to hexadecimal
        const rawIdHex = bufferToHex(credential.rawId);
        console.log("Converted rawId (Hex):", rawIdHex);

        // Use ethers.keccak256 to hash the rawIdHex
        const hashedRawId = ethers.keccak256(ethers.toUtf8Bytes(rawIdHex));

        // Create a wallet using the hashed seed
        const wallet = new ethers.Wallet(hashedRawId);

        console.log("Passkey registered successfully!");
        console.log("Derived Wallet Address:", wallet.address);

        walletOutput.value = `Wallet created successfully!\nAddress: ${wallet.address}`;
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
async function authenticateWallet() {
    try {
        const challenge = new Uint8Array(32);
        window.crypto.getRandomValues(challenge);

        console.log("Attempting authentication with challenge:", challenge);

        const assertion = await navigator.credentials.get({
            publicKey: {
                challenge: challenge,
                userVerification: "preferred",
            }
        });

        if (!assertion || !assertion.rawId) {
            throw new Error("Failed to retrieve assertion or rawId.");
        }

        console.log("Assertion received:", assertion);

        // Convert rawId to hexadecimal
        const rawIdHex = bufferToHex(assertion.rawId);
        console.log("Converted rawId (Hex):", rawIdHex);

        // Derive wallet deterministically
        const hashedRawId = ethers.keccak256(ethers.toUtf8Bytes(rawIdHex));
        const wallet = new ethers.Wallet(hashedRawId);

        console.log("Wallet authenticated successfully:", wallet.address);
        return wallet;
    } catch (error) {
        console.error("Error during WebAuthn authentication:", error);
        alert(`Failed to authenticate wallet: ${error.message}`);
        throw error;
    }
}


/**
 * Updates the wallet balance.
 */
async function updateWalletBalance(wallet) {
    try {
        const provider = new ethers.JsonRpcProvider(GNOSIS_RPC_URL);
        const balance = await provider.getBalance(wallet.address);
        const formattedBalance = ethers.formatEther(balance);
        walletBalanceDiv.textContent = `Balance: ${formattedBalance} xDAI`;
    } catch (error) {
        console.error("Error fetching wallet balance:", error);
        walletBalanceDiv.textContent = "Balance: Error fetching balance";
    }
}

// Create Wallet
createWalletButton.addEventListener("click", async () => {
    try {
        const wallet = await registerPasskey();
        walletOutput.value = `Wallet created successfully!\nAddress: ${wallet.address}`;
        console.log("Wallet Address:", wallet.address);
        updateWalletBalance(wallet); // Fetch and display balance
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
        updateWalletBalance(wallet); // Fetch and display balance
    } catch (error) {
        console.error("Error loading wallet:", error);
        alert("Failed to load wallet. Ensure you authenticate correctly.");
    }
});

// Send Funds
sendFundsButton.addEventListener("click", async () => {
    const recipient = recipientInput.value.trim();
    const amount = parseFloat(amountInput.value);

    if (!ethers.isAddress(recipient)) {
        alert("Invalid recipient address!");
        return;
    }

    if (isNaN(amount) || amount <= 0) {
        alert("Invalid amount!");
        return;
    }

    try {
        const wallet = await authenticateWallet();
        const provider = new ethers.JsonRpcProvider(GNOSIS_RPC_URL);
        const walletWithProvider = wallet.connect(provider);

        const tx = await walletWithProvider.sendTransaction({
            to: recipient,
            value: ethers.parseEther(amount.toString())
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

    
