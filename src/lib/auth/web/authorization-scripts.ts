/** Atomically validates and consumes a single-use Firebase identity handoff. */
export const consumeWebAuthorizationIdentityTicketScript = `
local raw = redis.call('GET', KEYS[1])

if not raw then
	return false
end

local ticket = cjson.decode(raw)

if ARGV[1] >= ticket.expiresAt then
	return false
end

redis.call('DEL', KEYS[1])

return raw
`;

/** Atomically replaces a browser authorization request with a short-lived grant. */
export const completeWebAuthorizationScript = `
local raw = redis.call('GET', KEYS[1])

if not raw then
	return 0
end

local request = cjson.decode(raw)

if request.browserTokenHash ~= ARGV[1]
	or ARGV[2] >= request.expiresAt
then
	return 0
end

if redis.call('EXISTS', KEYS[2]) == 1 then
	return 0
end

redis.call('DEL', KEYS[1])
redis.call(
	'SET',
	KEYS[2],
	ARGV[3],
	'PX',
	ARGV[4],
	'NX'
)

return 1
`;

/** Atomically validates and consumes a single-use Web authorization grant. */
export const consumeWebAuthorizationGrantScript = `
local raw = redis.call('GET', KEYS[1])

if not raw then
	return false
end

local grant = cjson.decode(raw)

if grant.applicationId ~= ARGV[1]
	or grant.redirectUri ~= ARGV[2]
	or grant.codeChallenge ~= ARGV[3]
	or grant.state ~= ARGV[4]
	or ARGV[5] >= grant.expiresAt
then
	return false
end

redis.call('DEL', KEYS[1])

return raw
`;

/** Atomically binds a Firebase ID token to an active passkey authorization. */
export const bindWebAuthorizationIdentityTokenScript = `
local raw = redis.call('GET', KEYS[1])

if not raw then
	return 0
end

local request = cjson.decode(raw)

if request.browserTokenHash ~= ARGV[1]
	or request.identity.userId ~= ARGV[2]
	or (request.identity.idToken ~= nil and request.identity.idToken ~= cjson.null)
	or ARGV[4] >= request.expiresAt
then
	return 0
end

request.identity.idToken = ARGV[3]

redis.call('SET', KEYS[1], cjson.encode(request), 'KEEPTTL')

return 1
`;

/** Atomically binds the account discovered from a verified passkey. */
export const bindWebAuthorizationPasskeyUserScript = `
local raw = redis.call('GET', KEYS[1])

if not raw then
	return 0
end

local request = cjson.decode(raw)

if request.browserTokenHash ~= ARGV[1]
	or request.identity.userId ~= cjson.null
	or request.identity.idToken ~= cjson.null
	or ARGV[3] >= request.expiresAt
then
	return 0
end

request.identity.userId = ARGV[2]
request.identity.idToken = cjson.null

redis.call('SET', KEYS[1], cjson.encode(request), 'KEEPTTL')

return 1
`;
