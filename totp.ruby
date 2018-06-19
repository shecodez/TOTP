# source: http://gofreerange.com/understanding-one-time-passwords

require 'openssl'

def generate_otp(key, counter, digits = 10)
  #counter = Time.now.to_i / 30
  counter_as_byte_string = [counter].pack('Q>')

  digest = OpenSSL::Digest.new('sha512')
  hmac = OpenSSL::HMAC.digest(digest, key, counter_as_byte_string)

  offset = hmac.bytes.last & 0x0f
  bytes = hmac.bytes[offset..offset + 3]
  bytes[0] = bytes[0] & 0x7f
  bytes_as_integer = (bytes[0] << 24) + (bytes[1] << 16) + (bytes[2] << 8) + bytes[3]

  bytes_as_integer.modulo(10 ** digits)
end

otp = generate_otp('ninja@example.comHDECHALLENGE003', 46502321)
puts "OTP: %s" % otp

# output: OTP: 1264436375
