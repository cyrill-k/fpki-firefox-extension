const errorTypes = {
    INVALID_CONFIG: "Invalid configuration"
}

class FpkiError extends Error {
    constructor(errorType, message) {
        console.log(errorType);
        console.log(message);
        console.log(errorType+": "+message);
        super(errorType+": "+message);
        this.errorType = errorType;
    }
}

export {
    errorTypes,
    FpkiError
}
