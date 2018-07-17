require 'openssl'
require 'bitcoin'
require 'ffi'
require './tools.rb'
include Util

require 'yaml'
require 'pp'

str  = ARGF.read()
data = YAML.load(str)

Bitcoin.network = :regtest
#
# segwit = Segwit.new
# txin = Txin.build do |input|
#   data['input'].each do |list|
#     input.prev_txid = list['prev_txid']
#     input.prev_output_index = list['prev_output_index'][0]
#   end
# end
# # segwit
# segwit.prev_outpoint_serialize(txin).hash_prevoutpoints
# segwit.prev_sequence_serialize(txin).hash_sequence
#
# txouts = []
# data['output'].each do |d|
#   txout = Txout.build do |output|
#     output.consume = d['consume']
#     output.script = Script.new.script(d)
#   end
#   # segwit
#   segwit.output_serialize(txout).hash_output
#   txouts.push(txout)
# end

# tx = Tx.build do |tx|
#   tx.version = data['version']
#   tx.locktime = data['locktime']
#   tx.hash_code = data['hash_code']
#   tx.input_count = data['input_count']
#   tx.output_count = data['output_count']
#   tx.in = txins
#   tx.out = txouts
# end
txins = []
txin = Txin.build do |input|
  data['input'].each do |list|
    input.prev_txid = list['prev_txid']
    input.prev_output_index = list['prev_output_index'][0]
  end
end
txins.push txin

txouts = []
txout = Txout.build do |output|
  data['output'].each do |d|
    output.consume = d['consume']
    output.script = Script.new.script(d)
  end
end
txouts.push txout

tx = Tx.build do |tx|
  tx.version = data['version']
  tx.locktime = data['locktime']
  tx.hash_code = data['hash_code']
  tx.input_count = data['input_count']
  tx.output_count = data['output_count']
  tx.in = txins
  tx.out = txouts
end
#tx.for_sig

hash_preimage = []
hash_preimage.push to_little(sprintf("%08x", data['version'])) # version

hash_preimage.push segwit.hash_prevouts  # hash_prevouts
sequence = 'ffffffff'
hash_preimage.push double_sha256(sequence) # hash_sequence

hash_preimage.push segwit.serialized_prev_outpoint # outpoint

signer = 'bcrt1qsus5n9a726cwkwp8fuyzu3wksj2m9yfked5anj'
sender_key_obj = address2keyobject signer
pubkey_hash = HASH160(sender_key_obj.pub)
script_code = "1976a914#{pubkey_hash}88ac"
hash_preimage.push script_code # script code
hash_preimage.push to_little(sprintf("%016x", 4900000000)) # input amount
hash_preimage.push to_little('ffffffff') # sequence
hash_preimage.push segwit.hash_output # hash_output

hash_preimage.push '00000000' # locktime
hash_preimage.push '01000000' # hash type
hashed_pre_sign = double_sha256(hash_preimage.join)
script_sig = []

#to p2sh, p2pkh
data['input'].each do |hash|
  hash['signer'].each do |signer|
    sender_key_obj = address2keyobject signer
    sig_obj = Signature.new(sender_key_obj.priv)
    if !sig_obj.sign(hashed_pre_sign).to_hash.bip62.der_check then
      STDERR.puts 'der check failed'
      exit(false)
    end
    signature = int2hex(hex_bytesize(sig_obj.signature)) + sig_obj.signature + int2hex(hex_bytesize(sender_key_obj.pub)) + sender_key_obj.pub
    script_sig.push(signature)
  end
end

final_tx = []
final_tx.push tx.version
final_tx.push '00' # marker
final_tx.push '01' # flag
final_tx.push '01' + tx.in[0].pack
final_tx.push '01' + tx.out[0].pack
final_tx.push '02' + script_sig[0]
final_tx.push '00000000' # locktime
p final_tx.join
