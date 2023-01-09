export const errorTypes = {
    INVALID_CONFIG: "Invalid configuration",
    INTERNAL_ERROR: "Internal plugin error",
    MAPSERVER_NETWORK_ERROR: "Mapserver network connection error",
    LEGACY_MODE_VALIDATION_ERROR: "Legacy mode validation error",
    POLICY_MODE_VALIDATION_ERROR: "Policy mode validation error"
}

export class FpkiError extends Error {
    constructor(errorType, message) {
        super(errorType+": "+message);
        this.errorType = errorType;
    }
}
