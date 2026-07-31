/* Sufficit Identity — WebAuthn browser adapter.
 *
 * The identity runtime owns every passkey rule. This file only crosses the
 * browser boundary required by WebAuthn and preserves the antiforgery token
 * rendered by the account UI.
 */

(function () {
    "use strict";

    const endpoints = Object.freeze({
        creationOptions: "/account/passkeys/creation-options",
        register: "/account/passkeys/register",
        requestOptions: "/account/passkeys/request-options",
        authenticate: "/account/passkeys/authenticate",
    });

    function failure(code, description) {
        return {
            succeeded: false,
            errors: [{ code, description }],
            state: null,
        };
    }

    function base64urlToBuffer(value) {
        const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
        const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
        const binary = atob(padded);
        const bytes = new Uint8Array(binary.length);
        for (let index = 0; index < binary.length; index += 1) {
            bytes[index] = binary.charCodeAt(index);
        }
        return bytes.buffer;
    }

    function bufferToBase64url(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = "";
        for (let index = 0; index < bytes.length; index += 1) {
            binary += String.fromCharCode(bytes[index]);
        }
        return btoa(binary)
            .replace(/\+/g, "-")
            .replace(/\//g, "_")
            .replace(/=+$/, "");
    }

    function parseCreationOptions(options) {
        if (typeof PublicKeyCredential.parseCreationOptionsFromJSON === "function") {
            return PublicKeyCredential.parseCreationOptionsFromJSON(options);
        }

        options.challenge = base64urlToBuffer(options.challenge);
        options.user.id = base64urlToBuffer(options.user.id);
        options.excludeCredentials = (options.excludeCredentials || []).map((credential) => ({
            ...credential,
            id: base64urlToBuffer(credential.id),
        }));
        return options;
    }

    function parseRequestOptions(options) {
        if (typeof PublicKeyCredential.parseRequestOptionsFromJSON === "function") {
            return PublicKeyCredential.parseRequestOptionsFromJSON(options);
        }

        options.challenge = base64urlToBuffer(options.challenge);
        options.allowCredentials = (options.allowCredentials || []).map((credential) => ({
            ...credential,
            id: base64urlToBuffer(credential.id),
        }));
        return options;
    }

    function serializeCredential(credential) {
        if (typeof credential.toJSON === "function") {
            return credential.toJSON();
        }

        const response = credential.response;
        const serialized = {
            id: credential.id,
            rawId: bufferToBase64url(credential.rawId),
            type: credential.type,
            response: {
                clientDataJSON: bufferToBase64url(response.clientDataJSON),
            },
            clientExtensionResults: credential.getClientExtensionResults
                ? credential.getClientExtensionResults()
                : {},
        };

        if ("attestationObject" in response) {
            serialized.response.attestationObject = bufferToBase64url(response.attestationObject);
            serialized.response.transports = response.getTransports
                ? response.getTransports()
                : [];

            const publicKey = response.getPublicKey ? response.getPublicKey() : null;
            if (publicKey) {
                serialized.response.publicKey = bufferToBase64url(publicKey);
            }

            const publicKeyAlgorithm = response.getPublicKeyAlgorithm
                ? response.getPublicKeyAlgorithm()
                : null;
            if (publicKeyAlgorithm !== null) {
                serialized.response.publicKeyAlgorithm = publicKeyAlgorithm;
            }

            const authenticatorData = response.getAuthenticatorData
                ? response.getAuthenticatorData()
                : null;
            if (authenticatorData) {
                serialized.response.authenticatorData = bufferToBase64url(authenticatorData);
            }
        } else {
            serialized.response.authenticatorData = bufferToBase64url(response.authenticatorData);
            serialized.response.signature = bufferToBase64url(response.signature);
            serialized.response.userHandle = response.userHandle
                ? bufferToBase64url(response.userHandle)
                : null;
        }

        if (credential.authenticatorAttachment) {
            serialized.authenticatorAttachment = credential.authenticatorAttachment;
        }

        return serialized;
    }

    async function postForm(url, form, values) {
        const body = new FormData(form);
        Object.entries(values || {}).forEach(([key, value]) => body.set(key, value));

        let response;
        try {
            response = await fetch(url, {
                method: "POST",
                body,
                credentials: "same-origin",
                cache: "no-store",
                headers: { Accept: "application/json" },
            });
        } catch {
            return {
                response: null,
                payload: failure(
                    "network-unavailable",
                    "Não foi possível acessar o serviço de identidade. Verifique a conexão e tente novamente."),
            };
        }

        const contentType = response.headers.get("content-type") || "";
        if (!contentType.includes("application/json")) {
            const authenticationWasLost = response.redirected
                || response.status === 401
                || response.status === 403;
            return {
                response,
                payload: failure(
                    authenticationWasLost ? "session-expired" : "invalid-response",
                    authenticationWasLost
                        ? "A página ou a sessão expirou. Recarregue a página e tente novamente."
                        : "O serviço retornou uma resposta inválida. Recarregue a página e tente novamente."),
            };
        }

        try {
            return { response, payload: await response.json() };
        } catch {
            return {
                response,
                payload: failure(
                    "invalid-response",
                    "O serviço retornou uma resposta inválida. Recarregue a página e tente novamente."),
            };
        }
    }

    function interactionFailure(error) {
        if (error && error.name === "NotAllowedError") {
            return failure(
                "passkey-interaction-cancelled",
                "A operação foi cancelada ou expirou. Inicie novamente quando estiver pronto.");
        }

        return failure(
            "passkey-interaction-failed",
            "O dispositivo não conseguiu concluir a operação com a passkey.");
    }

    window.passkeys = window.passkeys || {};

    window.passkeys.register = async function (form, name) {
        if (!window.PublicKeyCredential || !navigator.credentials) {
            return failure(
                "passkey-unsupported",
                "Este navegador não oferece suporte a passkeys neste dispositivo.");
        }

        const optionsResponse = await postForm(endpoints.creationOptions, form);
        if (!optionsResponse.response || !optionsResponse.response.ok) {
            return optionsResponse.payload;
        }

        let credential;
        try {
            credential = await navigator.credentials.create({
                publicKey: parseCreationOptions(optionsResponse.payload),
            });
        } catch (error) {
            return interactionFailure(error);
        }

        if (!credential) {
            return failure(
                "passkey-credential-missing",
                "O dispositivo não retornou uma passkey.");
        }

        const registerResponse = await postForm(endpoints.register, form, {
            credentialJson: JSON.stringify(serializeCredential(credential)),
            name: name || "",
        });
        return registerResponse.payload;
    };

    window.passkeys.signIn = async function (form, username) {
        if (!window.PublicKeyCredential || !navigator.credentials) {
            return failure(
                "passkey-unsupported",
                "Este navegador não oferece suporte a passkeys neste dispositivo.");
        }

        const query = username
            ? `?username=${encodeURIComponent(username)}`
            : "";
        const optionsResponse = await postForm(
            `${endpoints.requestOptions}${query}`,
            form);
        if (!optionsResponse.response || !optionsResponse.response.ok) {
            return optionsResponse.payload;
        }

        let credential;
        try {
            credential = await navigator.credentials.get({
                publicKey: parseRequestOptions(optionsResponse.payload),
            });
        } catch (error) {
            return interactionFailure(error);
        }

        if (!credential) {
            return failure(
                "passkey-credential-missing",
                "O dispositivo não retornou uma passkey.");
        }

        const authenticationResponse = await postForm(endpoints.authenticate, form, {
            credentialJson: JSON.stringify(serializeCredential(credential)),
        });
        return authenticationResponse.payload;
    };

    window.passkeys.isSupported = async function () {
        if (!window.PublicKeyCredential || !navigator.credentials) {
            return false;
        }

        try {
            if (PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) {
                return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
            }
        } catch {
            // External USB/NFC authenticators can still work without a platform authenticator.
        }

        return true;
    };
})();
