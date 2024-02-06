export const errorTypes = {
    INVALID_CONFIG: "Invalid configuration",
    INTERNAL_ERROR: "Internal plugin error",
    MAPSERVER_NETWORK_ERROR: "Map server network connection error",
    LEGACY_MODE_VALIDATION_ERROR: "Legacy mode validation error",
    POLICY_MODE_VALIDATION_ERROR: "Policy mode validation error",
    MAPSERVER_INVALID_RESPONSE: "Map server returned invalid response",
}

export class FpkiError extends Error {
    constructor(errorType, message) {
        super(errorType+": "+message);
        this.errorType = errorType;
    }
}
