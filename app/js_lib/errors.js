export const errorTypes = {
    INVALID_CONFIG: "Invalid configuration",
    INTERNAL_ERROR: "Internal plugin error"
}

export class FpkiError extends Error {
    constructor(errorType, message) {
        super(errorType+": "+message);
        this.errorType = errorType;
    }
}
