#!lua name=hedis_test

local function set_operations(keys, args)
  local count = tonumber(args[1])
  for i = 1,count,1
  do
    redis.call('SET', keys[i], args[i+1])
  end
  return redis.status_reply('OK')
end

redis.register_function('set_operations', set_operations)
