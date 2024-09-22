$(window).on('load', function () {
    $("#registePasswordless").on('click', () => registerPasswordlessButtonClicked());
    $("#authenticatefido").on('click', () => authenticateFido());
    $("#conditionalRegistration").on('click', () => conditionalRegistrationButtonClicked());
});

const abortController = new AbortController();
const abortSignal = abortController.signal;

/**
 * Register
 */
function registerPasswordlessButtonClicked() {
    getRegChallenge()
        .then(createCredentialOptions => {
            return createCredential(createCredentialOptions, false);
        })
        .then(() => {
            $("#statusPasswordless").text("Successfully created credential");
        })
        .catch(e => {
            $("#statusPasswordless").text("Error: " + e);
        });
}

async function conditionalRegistrationButtonClicked() {
    if (!(await isConditionalRegistrationEnable())) {
        return;
    }

    getRegChallenge()
        .then(createCredentialOptions => {
            return createCredential(createCredentialOptions, true);
        })
        .then(() => {
            $("#statusConditionalRegistration").text("Successfully created credential");
        })
        .catch(e => {
            $("#statusConditionalRegistration").text("Error: " + e);
        });
}

async function isConditionalRegistrationEnable() {
    // Check if PublicKeyCredential is supported in the current browser
    if (typeof PublicKeyCredential === 'undefined') {
        $("#statusConditionalRegistration").text("Error: PublicKeyCredential is not supported in this browser.");
        return false;
    }

    // Check if getClientCapabilities method exists on PublicKeyCredential
    if (typeof PublicKeyCredential.getClientCapabilities === 'function') {
        try {
            let capabilities = await PublicKeyCredential.getClientCapabilities();
            if (!capabilities.conditionalCreate) {
                $("#statusConditionalRegistration").text("Conditional create is not supported. Do not continue with mediation.");
                // Do not continue with mediation
            } else {
                console.log("Conditional create is supported. Continue with mediation.");
                // Continue with mediation
                return true;
            }
        } catch (error) {
            $("#statusConditionalRegistration").text("Error getting client capabilities:" + error);
            // Handle the error appropriately
        }
    } else {
        $("#statusConditionalRegistration").text("Error: getClientCapabilities is not supported in this browser");
        // Handle the case where the method is not supported
    }
    return false;
}

/**
 * Authenticate
 */
function authenticateFidoWithConditional() {
    if(PublicKeyCredential.isConditionalMediationAvailable &&
        PublicKeyCredential.isConditionalMediationAvailable()) {
        authenticateFido();
    } else {
        $("#conditionalUIArea").hide();
        $("#modalUiArea").show();
        $("#authenticatefidoStatus").text("Browser doesn\'t support Conditional UI.");
    }
}

function authenticateFido() {
    getAuthChallenge()
        .then(getCredentialOptions => {
            return getAssertion(getCredentialOptions);
        })
        .then(assertion => {
            $("#assertion").val(JSON.stringify(assertion));
            document.authenticate.submit();
        })
        .catch(e => {
            $("#status").text("Error: " + e);
        });
}

function getRegChallenge() {
    return rest_post("/register/option")
        .then(response => {
            logObject("Get reg challenge response", response);
            if (response.status !== 'ok') {
                return Promise.reject(response.errorMessage);
            } else {
                let createCredentialOptions = performMakeCredReq(response);
                return Promise.resolve(createCredentialOptions);
            }
        });
}

function getAuthChallenge() {
    return rest_post("/authenticate/option")
        .then(response => {
            logObject("Get auth challenge", response);
            if (response.status !== 'ok') {
                return Promise.reject(response.errorMessage);
            } else {
                let getCredentialOptions = performGetCredReq(response);
                return Promise.resolve(getCredentialOptions);
            }
        });
}

function rest_post(endpoint, object) {
    return fetch(endpoint, {
            method: "POST",
            credentials: "same-origin",
            body: JSON.stringify(object),
            headers: {
                "content-type": "application/json"
            }
        })
        .then(response => {
            return response.json();
        });
}

function logObject(name, object) {
    console.log(name + ": " + JSON.stringify(object));
}

function logVariable(name, text) {
    console.log(name + ": " + text);
}

function removeEmpty(obj) {
    for (let key in obj) {
        if (obj[key] == null || obj[key] === "") {
            delete obj[key];
        } else if (typeof obj[key] === 'object') {
            removeEmpty(obj[key]);
        }
    }
}

let performMakeCredReq = (makeCredReq) => {
    makeCredReq.challenge = base64UrlDecode(makeCredReq.challenge);
    makeCredReq.user.id = base64UrlDecode(makeCredReq.user.id);

    //Base64url decoding of id in excludeCredentials
    if (makeCredReq.excludeCredentials instanceof Array) {
        for (let i of makeCredReq.excludeCredentials) {
            if ('id' in i) {
                i.id = base64UrlDecode(i.id);
            }
        }
    }

    delete makeCredReq.status;
    delete makeCredReq.errorMessage;

    removeEmpty(makeCredReq);

    logObject("Updating credentials ", makeCredReq)
    return makeCredReq;
}

function base64UrlDecode(base64url) {
    let input = base64url
        .replace(/-/g, "+")
        .replace(/_/g, "/");
    let diff = input.length % 4;
    if (!diff) {
        while(diff) {
            input += '=';
            diff--;
        }
    }

    return Uint8Array.from(atob(input), c => c.charCodeAt(0));
}

function base64UrlEncode(arrayBuffer) {
    if (!arrayBuffer || arrayBuffer.length === 0) {
        return undefined;
    }

    return btoa(String.fromCharCode.apply(null, new Uint8Array(arrayBuffer)))
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
}

function createCredential(options, addMediation) {
    if (!PublicKeyCredential || typeof PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable !== "function") {
        return Promise.reject("WebAuthn APIs are not available on this user agent.");
    }

    let publicKeyCredentialCreationOptions = {
        publicKey: options,
        ...(addMediation && { mediation: "conditional" })
    };

    return navigator.credentials.create(publicKeyCredentialCreationOptions)
        .then(createResponse => {
            let publicKeyCredential = {
                id: base64UrlEncode(createResponse.rawId),
                response : {
                    clientDataJSON: base64UrlEncode(createResponse.response.clientDataJSON),
                    attestationObject: base64UrlEncode(createResponse.response.attestationObject)
                },
                type: createResponse.type,
            };

            if (createResponse.getClientExtensionResults) {
                publicKeyCredential.clientExtensionResults = createResponse.getClientExtensionResults();
            }

            // set transports if it is available
            if (typeof createResponse.response.getTransports === "function") {
                publicKeyCredential.response.transports = createResponse.response.getTransports();
            }

            logObject("=== PublicKeyCredential ===", publicKeyCredential);

            return rest_post("/register/verify", publicKeyCredential);
        })
        .catch(function(error) {
            logVariable("create credential error", error);
            if (error === "AbortError") {
                console.info("Aborted by user");
            }
            return Promise.reject(error);
        })
        .then(response => {
            if (response.status !== 'ok') {
                return Promise.reject(response.errorMessage);
            } else {
                return Promise.resolve(response);
            }
        });
}

let performGetCredReq = (getCredReq) => {
    getCredReq.challenge = base64UrlDecode(getCredReq.challenge);

    //Base64url decoding of id in allowCredentials
    if (getCredReq.allowCredentials instanceof Array) {
        for (let i of getCredReq.allowCredentials) {
            if ('id' in i) {
                i.id = base64UrlDecode(i.id);
            }
        }
    }

    delete getCredReq.status;
    delete getCredReq.errorMessage;

    removeEmpty(getCredReq);

    logObject("Updating credentials ", getCredReq)
    return getCredReq;
}

function getAssertion(options) {
    if (!PublicKeyCredential) {
        return Promise.reject("WebAuthn APIs are not available on this user agent.");
    }

    let publicKeyCredentialRequestOptions = {
        publicKey: options,
        signal: abortSignal,
    };

    // Level3 Conditional UI
    if(PublicKeyCredential.isConditionalMediationAvailable &&
       PublicKeyCredential.isConditionalMediationAvailable()) {
        publicKeyCredentialRequestOptions.mediation = "conditional";
    }

    return navigator.credentials.get(publicKeyCredentialRequestOptions)
        .then(getResponse => {
            let publicKeyCredential = {
                id: base64UrlEncode(getResponse.rawId),
                response: {
                    clientDataJSON: base64UrlEncode(getResponse.response.clientDataJSON),
                    userHandle: base64UrlEncode(getResponse.response.userHandle),
                    signature: base64UrlEncode(getResponse.response.signature),
                    authenticatorData: base64UrlEncode(getResponse.response.authenticatorData)
                },
                type: getResponse.type,
            };

            if (getResponse.getClientExtensionResults) {
                publicKeyCredential.clientExtensionResults = getResponse.getClientExtensionResults();
            }

            logObject("=== PublicKeyCredential ===", publicKeyCredential);

            return Promise.resolve(publicKeyCredential);
        })
        .catch(function(error) {
            logVariable("get assertion error", error);
            if (error === "AbortError") {
                console.info("Aborted by user");
            }
            return Promise.reject(error);
        });
}
