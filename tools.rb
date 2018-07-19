module Util
  # big endien to little endien
  #
  # @param hex_string [string] hex string
  # @return [str] hex string
  def to_little hex_string
    [hex_string].pack('H*').reverse.unpack('H*').first
  end

  # calcurate bytesize of hex
  #
  # @param hex [string]
  # @return [int]
  def hex_bytesize hex
    [hex].pack("H*").bytesize
  end

  # convert integer to hex string
  #
  # @param integer [int]
  # @return [string] hex string
  def int2hex integer
    integer.to_s(16)
  end

  def to_var_int integer, byte_size=1
    sprintf("%00#{byte_size*2}X", integer)
  end

  def sign target, priv_key
    sigobj = OpenSSL::PKey::EC.new('secp256k1')
    sigobj.private_key = OpenSSL::BN.new(priv_key, 16)
    signature = sigobj.dsa_sign_asn1([target].pack("H*")).unpack("H*")
    Signature.bip62 signature[0]+"01"
  end

  # double hash payload
  #
  # @param payload [string] hex string
  # @return hex string
  def double_sha256 payload
    OpenSSL::Digest::SHA256.hexdigest([OpenSSL::Digest::SHA256.hexdigest([payload].pack("H*"))].pack("H*"))
  end

  # sha256 and ripimd160
  #
  # @param payload [string] hex string
  # @return hex string
  def HASH160 payload
    OpenSSL::Digest::RIPEMD160.hexdigest([OpenSSL::Digest::SHA256.hexdigest([payload].pack("H*"))].pack("H*"))
  end

  # address to bitcoin-ruby key object
  #
  # @param address [string]
  # @return [Bitcoin::Key]
  def address2keyobject address
    priv_wif = `~/bitcoin/src/bitcoin-cli dumpprivkey #{address}`.chomp
    Bitcoin::Key.from_base58(priv_wif)
  end

  def varint data
    byte_size = hex_bytesize data
    if byte_size < 253
      sprintf("%02x", byte_size)
    elsif byte_size <= 65535
      'fd' + to_little(sprintf("%04x", byte_size))
    elsif byte_size <= 4294967295
      'fe' + to_little(sprintf("%08x", byte_size))
    end
  end

  # fill first 0.5 byte with zero if number of characters of signature is odd.
  def fill_zero string
    if string.size % 2 != 0
      string = '0' + string
      string
    else
      string
    end
  end
end

class Segwit
  attr_reader :serialized_prev_outpoint, :hash_prevouts, :hash_sequence, :hash_output, :serialized_prev_sequence, :prev_txid
  attr_writer :tx, :txin, :txout

  def initialize
    @serialized_prev_outpoint = []
    @serialized_output = []
    @serialized_prev_sequence = []
  end

  def self.build
    segwit = self.new
    yield segwit
    segwit.prev_outpoint_serialize.hash_prevoutpoints
    segwit.prev_sequence_serialize.hash_sequence
    segwit.output_serialize.hash_output
    segwit
  end

  def prev_outpoint_serialize
    prev_outpoint = @txin.prev_txid + @txin.prev_output_index
    @serialized_prev_outpoint.push(prev_outpoint)
    self
  end

  def hash_prevoutpoints
    @hash_prevouts = double_sha256(@serialized_prev_outpoint.join)
  end

  def prev_sequence_serialize
    p "prev_sequenc: #{@txin.sequence}"
    @serialized_prev_sequence.push(@txin.sequence)
    self
  end

  def hash_sequence
    @hash_sequence = double_sha256(@serialized_prev_sequence.join)
  end

  def output_serialize
    p "output: #{@txout.consume + @txout.script}"
    script = @txout.script
    @serialized_output.push(@txout.consume + int2hex(hex_bytesize(script)) + script)
    self
  end

  def hash_output
    p "output: #{@serialized_output.join}"
    @hash_output = double_sha256(@serialized_output.join)
  end

  def p2wpkh_script_code_from_address=(signer)
    pubkey_hash = HASH160(address2keyobject(signer).pub)
    @script_code = "1976a914#{pubkey_hash}88ac"
  end

  def pack
    p [@tx.version, @hash_prevouts, @hash_sequence, @serialized_prev_outpoint[0], @script_code, @txout.consume, @sequence, @hash_output, @tx.locktime, @tx.hash_code].join
  end
end

class Tx
  attr_accessor :in, :out, :version, :locktime, :hash_code, :input_count, :output_count, :segwit
  def serialize
    self.pack
  end

  def for_sig
    serialized_in = @in.map { |i| i.serialize }
    serialized_out = @out.map { |o| o.serialize }
    @version + @input_count + serialized_in.join + @output_count + serialized_out.join + @locktime + @hash_code
  end

  def pack
    serialized_in = @in.map { |i| i.serialize }
    serialized_out = @out.map { |o| o.serialize }
    @version + @input_count + serialized_in.join + @output_count + serialized_out.join + @locktime
  end

  def self.build
    tx = Tx.new
    yield tx
    tx
  end

  # integer to 4 bytes hex string
  #
  # @param vaersion [int]
  # @return [string] hex string
  def version=(version)
    @version = to_little(sprintf('%08X',  version)) #4bytes
  end

  def locktime=(locktime)
    @locktime = to_little locktime
  end

  def hash_code=(hash_code)
    @hash_code = to_little(sprintf('%08X', hash_code))
  end

  def input_count=(count)
    @input_count = to_little(sprintf("%02X", count))
  end

  def output_count=(count)
    @output_count = to_little(sprintf("%02X", count))
  end

  def in=(ins)
    @in = ins
  end

  def out=(outs)
    @out = outs
  end
end

class Txin < Tx
  attr_accessor :prev_txid, :prev_output_index, :script_size, :script, :sequence

  def initialize
    @hash_code = "01"
    @sequence = "ffffffff"
    @script = ''
  end

  def self.build
    input = Txin.new
    yield input
    input
  end

  def prev_txid=(id)
    @prev_txid = to_little id
  end

  def prev_output_index=(index)
    @prev_output_index = to_little sprintf("%08X", index)
  end

  def pack
    @script_size = varint(@script)
    @prev_txid + @prev_output_index + @script_size + @script + @sequence
  end

end

class Txout < Tx
  attr_accessor :script, :redeem_script
  attr_reader :consume, :script_size

  def initialize
    @script_size, @script= nil
  end

  def self.build
    output = Txout.new
    yield output
    output
  end

  def consume=(amount)
    @consume = to_little sprintf("%016X", amount) # 8 bytes
  end

  def pubkey_script=(address)
    key_obj = address2keyobject address
  end

  def pack
    @script_size = sprintf("%02x", hex_bytesize(@script))
    @consume + @script_size + @script
  end
end

class Script

  attr_reader :redeem_script

  OP_DUP = '76'
  OP_0 = '00'
  OP_2 = '52'
  OP_3 = '53'
  OP_CHECKSIG = 'ac'
  OP_CHECKMULTISIG = 'ae'
  OP_HASH160 = 'a9'
  OP_EQUAL = '87'
  OP_EQUALVERIFY = '88'

  # yaml data to script
  #
  # @param output [hash] from YAML
  # @return [string]
  def script output
    if output.key?('multisig')
      multisig_script output
    elsif output.key?('p2pkh')
      p2pkh_script output
    elsif output.key?('p2sh')
      p2sh_script output
    elsif output.key?('p2wpkh')
      output['p2wpkh']
    end
  end

  def p2sh_script output
    script_encoded = []
    output['p2sh'].split.each do |chunk|
      if chunk == "redeem_script_hash" then
        @redeem_script = multisig_script(output)
        p "redeem script: #{@redeem_script}"
        redeem_script_hash = HASH160(redeem_script)
        d = int2hex(hex_bytesize(redeem_script_hash)) + redeem_script_hash
      else
        d = eval(chunk)
      end
      script_encoded.push(d)
    end
    script_encoded.join
  end

  def p2pkh_script output
    script_encoded = []
    output['p2pkh'].split.each do |chunk|
      if chunk == "pubkey_hash" then
        pubkey_hash = HASH160(address2keyobject(output['address'][0]).pub)
        d = int2hex(hex_bytesize(pubkey_hash)) + pubkey_hash
      else
        d = eval(chunk)
      end
      script_encoded.push(d)
    end
    script_encoded.join
  end

  # hash data to script array
  #
  # @param output [hash] from YAML
  # @return [array] script
  def multisig_script output
    script_encoded = []
    output['multisig_script'].split.each do |chunk|
      if chunk == 'pubkeys' then
        output['address'].each do |address|
          pubkey = address2keyobject(address).pub
          script_encoded.push(int2hex(hex_bytesize(pubkey)) + pubkey)
        end
      else
        script_encoded.push(eval(chunk))
      end
    end
    script_encoded.join
  end
end

class Signature
  attr_accessor :s, :signature, :signature_hash

  def initialize priv_key
    @priv_key = priv_key
    @sighash = "01"
  end

  def sign data
    sigobj = OpenSSL::PKey::EC.new('secp256k1')
    sigobj.private_key = OpenSSL::BN.new(@priv_key, 16)
    signature = sigobj.dsa_sign_asn1([data].pack("H*")).unpack("H*")
    @signature = signature[0] + @sighash
    self
  end

  def bip62
    s_max = "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0"
    s_big = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
    s_int = @signature_hash['s'].to_i(16)
    @signature_hash
    if s_int > s_max.to_i(16) then
      p "s is big"
      low_s = s_big.to_i(16) - s_int
      @signature_hash['s'] = fill_zero(low_s.to_s(16))
      @signature_hash['s_length'] = int2hex(hex_bytesize(@signature_hash['s']))

      @signature = @signature_hash.values.join
      @signature_hash['total_length'] = int2hex(self.size - 3)
      @signature = @signature_hash.values.join
    end
    @signature = fill_zero(@signature)
    self
  end

  def der_check
    return false if self.size < 9
    return false if self.size > 73

    return false if @signature_hash['total_length'].to_i(16) != hex_bytesize(signature) - 3

    r_length = @signature_hash['r_length'].to_i(16)
    s_length = @signature_hash['s_length'].to_i(16)
    return false if r_length + 5 >= @signature.size
    return false if r_length + s_length + 7 != self.size
    return false if @signature_hash['prefix1'] != '02'
    return false if r_length == 0
    return false if @signature_hash['prefix2'] != '02'
    true
  end

  def to_hash
    keys = ['format', 'total_length', 'prefix1', 'r_length', 'r', 'prefix2', 's_length', 's', 'sighash']
    values = []
    sig_byte = @signature.unpack("a2"*(signature.length/2))
    values.push(sig_byte[0], sig_byte[1], sig_byte[2], sig_byte[3])
    values.push(sig_byte[4, sig_byte[3].to_i(16)].join) # push r
    next_of_r = 4 + sig_byte[3].to_i(16)
    sig_byte[next_of_r]
    s_size = sig_byte[next_of_r+1]
    values.push(sig_byte[next_of_r], s_size) # push 02 and s size
    values.push(sig_byte[next_of_r+2, s_size.to_i(16)].join) # push s
    values.push(sig_byte[-1])
    pairs = [keys, values].transpose
    @signature_hash = Hash[pairs]
    self
  end

  def size
    hex_bytesize(@signature)
  end
end
