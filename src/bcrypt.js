var SecureRandom = require('dw/crypto/SecureRandom');

/**
 * bcrypt namespace.
 * @type {Object.<string,*>}
 */
var bcrypt = {};

/**
 * Generates cryptographically secure random bytes.
 * @function
 * @param {number} len Bytes length
 * @returns {!Array.<number>} Random bytes
 * @throws {Error} If no random implementation is available
 * @inner
 */
function random(len) {
    // We use dw.crypto.SecureRandom to provide a source of randomness
    var random = new SecureRandom();
    return random.nextBytes(len);
}

/**
 * Synchronously generates a salt.
 * @param {number=} rounds Number of rounds to use, defaults to 10 if omitted
 * @param {number=} seed_length Not supported.
 * @returns {string} Resulting salt
 * @throws {Error} If a random fallback is required but not set
 */
bcrypt.genSaltSync = function(rounds, seed_length) {
    rounds = rounds || GENSALT_DEFAULT_LOG2_ROUNDS;
    if (typeof rounds !== 'number')
        throw Error("Illegal arguments: "+(typeof rounds)+", "+(typeof seed_length));
    if (rounds < 4)
        rounds = 4;
    else if (rounds > 31)
        rounds = 31;
    var salt = [];
    salt.push("$2a$");
    if (rounds < 10)
        salt.push("0");
    salt.push(rounds.toString());
    salt.push('$');
    salt.push(base64_encode(random(BCRYPT_SALT_LEN), BCRYPT_SALT_LEN)); // May throw
    return salt.join('');
};

/**
 * Synchronously generates a hash for the given string.
 * @param {string} s String to hash
 * @param {(number|string)=} salt Salt length to generate or salt to use, default to 10
 * @returns {string} Resulting hash
 */
bcrypt.hashSync = function(s, salt) {
    if (typeof salt === 'undefined')
        salt = GENSALT_DEFAULT_LOG2_ROUNDS;
    if (typeof salt === 'number')
        salt = bcrypt.genSaltSync(salt);
    if (typeof s !== 'string' || typeof salt !== 'string')
        throw Error("Illegal arguments: "+(typeof s)+', '+(typeof salt));
    return _hash(s, salt);
};

/**
 * Compares two strings of the same length in constant time.
 * @param {string} known Must be of the correct length
 * @param {string} unknown Must be the same length as `known`
 * @returns {boolean}
 * @inner
 */
function safeStringCompare(known, unknown) {
    var diff = known.length ^ unknown.length;
    for (var i = 0; i < known.length; ++i) {
        diff |= known.charCodeAt(i) ^ unknown.charCodeAt(i);
    }
    return diff === 0;
}

/**
 * Synchronously tests a string against a hash.
 * @param {string} s String to compare
 * @param {string} hash Hash to test against
 * @returns {boolean} true if matching, otherwise false
 * @throws {Error} If an argument is illegal
 */
bcrypt.compareSync = function(s, hash) {
    if (typeof s !== "string" || typeof hash !== "string")
        throw Error("Illegal arguments: "+(typeof s)+', '+(typeof hash));
    if (hash.length !== 60)
        return false;
    return safeStringCompare(bcrypt.hashSync(s, hash.substr(0, hash.length-31)), hash);
};

/**
 * Gets the number of rounds used to encrypt the specified hash.
 * @param {string} hash Hash to extract the used number of rounds from
 * @returns {number} Number of rounds used
 * @throws {Error} If `hash` is not a string
 */
bcrypt.getRounds = function(hash) {
    if (typeof hash !== "string")
        throw Error("Illegal arguments: "+(typeof hash));
    return parseInt(hash.split("$")[2], 10);
};

/**
 * Gets the salt portion from a hash. Does not validate the hash.
 * @param {string} hash Hash to extract the salt from
 * @returns {string} Extracted salt part
 * @throws {Error} If `hash` is not a string or otherwise invalid
 */
bcrypt.getSalt = function(hash) {
    if (typeof hash !== 'string')
        throw Error("Illegal arguments: "+(typeof hash));
    if (hash.length !== 60)
        throw Error("Illegal hash length: "+hash.length+" != 60");
    return hash.substring(0, 29);
};

//? include("bcrypt/util.js");

//? include("bcrypt/impl.js");

/**
 * Encodes a byte array to base64 with up to len bytes of input, using the custom bcrypt alphabet.
 * @function
 * @param {!Array.<number>} b Byte array
 * @param {number} len Maximum input length
 * @returns {string}
 */
bcrypt.encodeBase64 = base64_encode;

/**
 * Decodes a base64 encoded string to up to len bytes of output, using the custom bcrypt alphabet.
 * @function
 * @param {string} s String to decode
 * @param {number} len Maximum output length
 * @returns {!Array.<number>}
 */
bcrypt.decodeBase64 = base64_decode;
