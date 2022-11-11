export const errorTypes = {
    INVALID_CONFIG: "Invalid configuration"
}

export class FpkiError extends Error {
    constructor(errorType, message) {
        console.log(errorType);
        console.log(message);
        console.log(errorType+": "+message);
        super(errorType+": "+message);
        this.errorType = errorType;
    }
}
