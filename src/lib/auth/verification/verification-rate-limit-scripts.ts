/** Checks an existing progressive email-verification penalty. */
export const checkEmailVerificationLimitScript = `
local blockedUntil = tonumber(
	redis.call('HGET', KEYS[1], 'blockedUntil') or '0'
)

if blockedUntil > tonumber(ARGV[1]) then
	return cjson.encode({
		allowed = false,
		retryAfterMs = blockedUntil - tonumber(ARGV[1]),
		penaltyLevel = tonumber(
			redis.call('HGET', KEYS[1], 'level') or '1'
		),
		penaltyApplied = false
	})
end

return cjson.encode({
	allowed = true
})
`;

/** Reserves an initial verification email within a fixed window. */
export const reserveInitialVerificationEmailScript = `
local now = tonumber(ARGV[1])
local maximum = tonumber(ARGV[2])
local windowMs = tonumber(ARGV[3])

local blockedUntil = tonumber(
	redis.call('HGET', KEYS[1], 'blockedUntil') or '0'
)

if blockedUntil > now then
	return cjson.encode({
		allowed = false,
		retryAfterMs = blockedUntil - now,
		penaltyLevel = tonumber(
			redis.call('HGET', KEYS[1], 'level') or '1'
		),
		penaltyApplied = false
	})
end

local count = redis.call('INCR', KEYS[2])

if count == 1 then
	redis.call('PEXPIRE', KEYS[2], windowMs)
end

if count <= maximum then
	return cjson.encode({
		allowed = true
	})
end

return cjson.encode({
	allowed = false,
	requiresPenalty = true
})
`;

/** Applies the next progressive email-verification penalty. */
export const applyEmailVerificationPenaltyScript = `
local now = tonumber(ARGV[1])
local resetMs = tonumber(ARGV[2])
local blockedUntil = tonumber(
	redis.call('HGET', KEYS[1], 'blockedUntil') or '0'
)

if blockedUntil > now then
	return cjson.encode({
		allowed = false,
		retryAfterMs = blockedUntil - now,
		penaltyLevel = tonumber(
			redis.call('HGET', KEYS[1], 'level') or '1'
		),
		penaltyApplied = false
	})
end

local level = tonumber(
	redis.call('HGET', KEYS[1], 'level') or '0'
)

local lastPenaltyAt = tonumber(
	redis.call('HGET', KEYS[1], 'lastPenaltyAt') or '0'
)

if lastPenaltyAt == 0 or now - lastPenaltyAt >= resetMs then
	level = 0
end

level = math.min(level + 1, 4)

local durations = {
	tonumber(ARGV[3]),
	tonumber(ARGV[4]),
	tonumber(ARGV[5]),
	tonumber(ARGV[6])
}

local duration = durations[level]
local nextBlockedUntil = now + duration

redis.call(
	'HSET',
	KEYS[1],
	'level',
	level,
	'blockedUntil',
	nextBlockedUntil,
	'lastPenaltyAt',
	now
)

redis.call(
	'PEXPIRE',
	KEYS[1],
	resetMs + duration
)

return cjson.encode({
	allowed = false,
	retryAfterMs = duration,
	penaltyLevel = level,
	penaltyApplied = true
})
`;