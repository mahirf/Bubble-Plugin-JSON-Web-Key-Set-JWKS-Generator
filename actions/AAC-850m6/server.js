async function(properties, context) {
    try {
        // Load jose-node-cjs-runtime
        const jose = require('jose-node-cjs-runtime');

        // Default values for the keys
        const keySize = 2048;
        const keyUse = "sig";
        const alg = "RS256";

        // Generate the RSA key pair
        const { publicKey, privateKey } = await jose.generateKeyPair(alg, {
            extractable: true,
            modulusLength: keySize,
        });

        // Export keys to JWK format
        const exportedPrivateJWT = await jose.exportJWK(privateKey);
        const exportedPublicJWT = await jose.exportJWK(publicKey);

        // Calculate Key ID (kid) for the key set
        const kid = await jose.calculateJwkThumbprint(exportedPublicJWT);

        // Add extra fields like key use (use) and algorithm (alg)
        const privateJWT = { ...exportedPrivateJWT, kid, use: keyUse, alg };
        const publicJWT = { ...exportedPublicJWT, kid, use: keyUse, alg };

        // Create JWKS (JSON Web Key Set)
        const publicJWKS = { keys: [publicJWT] };
        const privateJWKS = { keys: [privateJWT] };

        // Return only JWKS
        return {
            publicJWKS: JSON.stringify(publicJWKS),
            privateJWKS: JSON.stringify(privateJWKS)
        };

    } catch (e) {
        throw new Error(`Failed to generate JWKS: ${e.message}`);
    }
}
