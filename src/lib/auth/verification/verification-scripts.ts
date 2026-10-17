/** Atomically creates a verification and its optional approval index. */
export const createVerificationScript = `
if redis.call('EXISTS', KEYS[1]) == 1 then
	return 0
end

if ARGV[4] == '1' and redis.call('EXISTS', KEYS[2]) == 1 then
	return 0
end

redis.call(
	'SET',
	KEYS[1],
	ARGV[1],
	'PX',
	ARGV[2],
	'NX'
)

if ARGV[4] == '1' then
	redis.call(
		'SET',
		KEYS[2],
		ARGV[3],
		'PX',
		ARGV[2],
		'NX'
	)
end

return 1
`;

/** Atomically validates an email code and updates its attempt count. */
export const attemptEmailCodeScript = `
local raw = redis.call('GET', KEYS[1])

if not raw then
	return cjson.encode({
		outcome = 'not_found'
	})
end

local item = cjson.decode(raw)

if item.userId ~= ARGV[1]
	or item.applicationId ~= ARGV[2]
	or item.browserTokenHash ~= ARGV[3]
	or item.mode ~= 'email_code'
then
	return cjson.encode({
		outcome = 'not_found'
	})
end

if ARGV[5] >= item.expiresAt then
	redis.call('DEL', KEYS[1])

	return cjson.encode({
		outcome = 'expired'
	})
end

if item.status == 'approved' then
	if item.codeHash ~= ARGV[4] then
		return cjson.encode({
			outcome = 'not_found'
		})
	end

	return cjson.encode({
		outcome = 'approved',
		verification = item
	})
end

if item.status ~= 'pending' then
	return cjson.encode({
		outcome = 'not_found'
	})
end

if item.failedAttempts >= item.maxAttempts then
	return cjson.encode({
		outcome = 'locked',
		newlyLocked = false
	})
end

if item.codeHash ~= ARGV[4] then
	item.failedAttempts = item.failedAttempts + 1

	redis.call(
		'SET',
		KEYS[1],
		cjson.encode(item),
		'KEEPTTL'
	)

	if item.failedAttempts >= item.maxAttempts then
		return cjson.encode({
			outcome = 'locked',
			newlyLocked = true
		})
	end

	return cjson.encode({
		outcome = 'invalid',
		remainingAttempts = item.maxAttempts - item.failedAttempts
	})
end

item.status = 'approved'
item.approvedAt = ARGV[5]

redis.call(
	'SET',
	KEYS[1],
	cjson.encode(item),
	'KEEPTTL'
)

return cjson.encode({
	outcome = 'approved',
	verification = item
})
`;

/** Atomically replaces an email verification code with throttling. */
export const resendEmailCodeScript = `
local raw = redis.call('GET', KEYS[1])

if not raw then
	return cjson.encode({
		outcome = 'not_found'
	})
end

local item = cjson.decode(raw)

if item.userId ~= ARGV[1]
	or item.applicationId ~= ARGV[2]
	or item.deviceId ~= ARGV[3]
	or item.browserTokenHash ~= ARGV[4]
	or item.mode ~= 'email_code'
	or item.status ~= 'pending'
then
	return cjson.encode({
		outcome = 'not_found'
	})
end

if ARGV[6] >= item.expiresAt then
	redis.call('DEL', KEYS[1])

	return cjson.encode({
		outcome = 'not_found'
	})
end

local resendCount = item.emailResendCount or 0

if resendCount >= tonumber(ARGV[9]) then
	return cjson.encode({
		outcome = 'limit_reached'
	})
end

local lastSentAt = item.emailLastSentAt or item.createdAt

if lastSentAt > ARGV[7] then
	return cjson.encode({
		outcome = 'cooldown',
		retryAfterMs = tonumber(ARGV[8])
	})
end

local previousTtl = redis.call('PTTL', KEYS[1])

if previousTtl <= 0 then
	return cjson.encode({
		outcome = 'not_found'
	})
end

redis.call(
	'SET',
	KEYS[2],
	raw,
	'PX',
	previousTtl
)

item.codeHash = ARGV[5]
item.failedAttempts = 0
item.emailResendCount = resendCount + 1
item.emailLastSentAt = ARGV[6]
item.expiresAt = ARGV[10]

redis.call(
	'SET',
	KEYS[1],
	cjson.encode(item),
	'PX',
	ARGV[11]
)

return cjson.encode({
	outcome = 'resent',
	verification = item
})
`;

/** Removes the rollback snapshot after successful email delivery. */
export const completeEmailCodeResendScript = `
local raw = redis.call('GET', KEYS[1])

if not raw then
	redis.call('DEL', KEYS[2])

	return 0
end

local item = cjson.decode(raw)

if item.userId ~= ARGV[1]
	or item.applicationId ~= ARGV[2]
	or item.deviceId ~= ARGV[3]
	or item.browserTokenHash ~= ARGV[4]
	or item.codeHash ~= ARGV[5]
	or item.mode ~= 'email_code'
	then
	return 0
end

redis.call('DEL', KEYS[2])

return 1
`;

/** Restores the previous email code after a delivery failure. */
export const rollbackEmailCodeResendScript = `
local currentRaw = redis.call('GET', KEYS[1])
local previousRaw = redis.call('GET', KEYS[2])

if not currentRaw or not previousRaw then
	return 0
end

local current = cjson.decode(currentRaw)
local previous = cjson.decode(previousRaw)

if current.userId ~= ARGV[1]
	or current.applicationId ~= ARGV[2]
	or current.deviceId ~= ARGV[3]
	or current.browserTokenHash ~= ARGV[4]
	or current.codeHash ~= ARGV[5]
	or current.mode ~= 'email_code'
	or current.status ~= 'pending'
	or previous.userId ~= ARGV[1]
	or previous.applicationId ~= ARGV[2]
	or previous.deviceId ~= ARGV[3]
	or previous.browserTokenHash ~= ARGV[4]
	or previous.mode ~= 'email_code'
	then
	return 0
end

local previousTtl = redis.call('PTTL', KEYS[2])

if previousTtl <= 0 then
	redis.call('DEL', KEYS[2])

	return 0
end

redis.call(
	'SET',
	KEYS[1],
	previousRaw,
	'PX',
	previousTtl
)

redis.call('DEL', KEYS[2])

return 1
`;

/** Atomically removes a browser-bound email verification. */
export const cancelEmailVerificationScript = `
local raw = redis.call('GET', KEYS[1])

if not raw then
	return 0
end

local item = cjson.decode(raw)

if item.userId ~= ARGV[1]
	or item.applicationId ~= ARGV[2]
	or item.deviceId ~= ARGV[3]
	or item.browserTokenHash ~= ARGV[4]
	or item.mode ~= 'email_code'
then
	return 0
end

if item.status ~= 'pending' and item.status ~= 'approved' then
	return 0
end

redis.call('DEL', KEYS[1])

return 1
`;

/** Atomically approves a pending mobile device verification. */
export const approveMobileScript = `
local verificationId = redis.call('GET', KEYS[2])

if not verificationId or verificationId ~= ARGV[1] then
	return nil
end

local raw = redis.call('GET', KEYS[1])

if not raw then
	redis.call('DEL', KEYS[2])

	return nil
end

local item = cjson.decode(raw)

if item.userId ~= ARGV[2]
	or item.applicationId ~= ARGV[3]
	or item.approvalTokenHash ~= ARGV[4]
	or item.mode ~= 'mobile_approval'
then
	return nil
end

if ARGV[5] >= item.expiresAt then
	redis.call('DEL', KEYS[1])
	redis.call('DEL', KEYS[2])

	return nil
end

if item.status == 'approved' then
	return cjson.encode(item)
end

if item.status ~= 'pending' then
	return nil
end

item.status = 'approved'
item.approvedAt = ARGV[5]

redis.call(
	'SET',
	KEYS[1],
	cjson.encode(item),
	'KEEPTTL'
)

return cjson.encode(item)
`;

/** Resolves a mobile verification using its approval secret. */
export const resolveMobileApprovalScript = `
local raw = redis.call('GET', KEYS[1])

if not raw then
	return nil
end

local item = cjson.decode(raw)

if item.userId ~= ARGV[1]
	or item.approvalTokenHash ~= ARGV[2]
	or item.mode ~= 'mobile_approval'
then
	return nil
end

if ARGV[3] >= item.expiresAt then
	return nil
end

if item.status ~= 'pending'
	and item.status ~= 'approved'
	and item.status ~= 'rejected'
then
	return nil
end

return cjson.encode(item)
`;

/** Resolves mobile verification state using its browser continuation secret. */
export const resolveBrowserMobileVerificationScript = `
local raw = redis.call('GET', KEYS[1])

if not raw then
	return nil
end

local item = cjson.decode(raw)

if item.userId ~= ARGV[1]
	or item.applicationId ~= ARGV[2]
	or item.deviceId ~= ARGV[3]
	or item.browserTokenHash ~= ARGV[4]
	or item.mode ~= 'mobile_approval'
then
	return nil
end

if ARGV[5] >= item.expiresAt then
	return nil
end

return cjson.encode(item)
`;

/** Atomically rejects a pending mobile device verification. */
export const rejectMobileScript = `
local verificationId = redis.call('GET', KEYS[2])

if not verificationId or verificationId ~= ARGV[1] then
	return nil
end

local raw = redis.call('GET', KEYS[1])

if not raw then
	return nil
end

local item = cjson.decode(raw)

if item.userId ~= ARGV[2]
	or item.approvalTokenHash ~= ARGV[3]
	or item.mode ~= 'mobile_approval'
then
	return nil
end

if ARGV[4] >= item.expiresAt then
	return nil
end

if item.status == 'rejected' then
	return cjson.encode(item)
end

if item.status ~= 'pending' then
	return nil
end

item.status = 'rejected'
item.rejectedAt = ARGV[4]

redis.call(
	'SET',
	KEYS[1],
	cjson.encode(item),
	'KEEPTTL'
)

return cjson.encode(item)
`;

/** Atomically begins a recoverable persistent device finalization. */
export const beginFinalizationScript = `
local raw = redis.call('GET', KEYS[1])

if not raw then
	return nil
end

local item = cjson.decode(raw)

if item.userId ~= ARGV[1]
	or item.applicationId ~= ARGV[2]
	or item.deviceId ~= ARGV[3]
	or item.browserTokenHash ~= ARGV[4]
then
	return nil
end

if item.status == 'approved' then
	if ARGV[5] >= item.expiresAt then
		redis.call('DEL', KEYS[1])

		return nil
	end

	item.status = 'finalizing'
	item.finalizingAt = ARGV[5]
	local retainedTtl = tonumber(ARGV[6])
	local remainingTtl = redis.call('PTTL', KEYS[1])

	if remainingTtl > retainedTtl then
		retainedTtl = remainingTtl
	end

	redis.call(
		'SET',
		KEYS[1],
		cjson.encode(item),
		'PX',
		retainedTtl
	)

	return cjson.encode(item)
end

if item.status == 'finalizing' or item.status == 'consumed' then
	local retainedTtl = tonumber(ARGV[6])
	local remainingTtl = redis.call('PTTL', KEYS[1])

	if remainingTtl < retainedTtl then
		redis.call('PEXPIRE', KEYS[1], retainedTtl)
	end

	return cjson.encode(item)
end

return nil
`;

/** Atomically completes persistent device finalization idempotently. */
export const completeFinalizationScript = `
local raw = redis.call('GET', KEYS[1])

if not raw then
	return nil
end

local item = cjson.decode(raw)

if item.userId ~= ARGV[1]
	or item.applicationId ~= ARGV[2]
	or item.deviceId ~= ARGV[3]
	or item.browserTokenHash ~= ARGV[4]
then
	return nil
end

if item.status == 'consumed' then
	redis.call('PEXPIRE', KEYS[1], ARGV[6])

	return cjson.encode(item)
end

if item.status ~= 'finalizing' then
	return nil
end

item.status = 'consumed'
item.consumedAt = ARGV[5]

redis.call(
	'SET',
	KEYS[1],
	cjson.encode(item),
	'PX',
	ARGV[6]
)

return cjson.encode(item)
`;
