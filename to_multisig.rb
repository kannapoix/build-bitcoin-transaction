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

txins = []
n = 0
data['input'].each do |list|
  txin = Txin.build do |input|
    input.prev_txid = list['prev_txid']
    input.prev_output_index = list['prev_output_index'][0]
    input.script = list['prev_pubkey_script']
  end
  txins.push(txin)
  n += 1
end
txins[0].pack

txouts = []
data['output'].each do |d|
  txout = Txout.build do |output|
    output.consume = d['consume']
    output.script = Script.new.script(d)
  end
  txouts.push(txout)
end

tx = Tx.build do |tx|
  tx.version = data['version']
  tx.locktime = data['locktime']
  tx.hash_code = data['hash_code']
  tx.input_count = data['input_count']
  tx.output_count = data['output_count']
  tx.in = txins
  tx.out = txouts
end
tx.for_sig

hashed_pre_sign = double_sha256(tx.for_sig)
script_sig = []

data['input'].each do |hash|
  hash['signer'].each do |signer|
    sender_key_obj = address2keyobject signer
    sig_obj = Signature.new(sender_key_obj.priv)
    if !sig_obj.sign(hashed_pre_sign).to_hash.bip62.der_check then
      p 'der check failed'
      exit
    end
    signature = int2hex(hex_bytesize(sig_obj.signature)) + sig_obj.signature + int2hex(hex_bytesize(sender_key_obj.pub)) + sender_key_obj.pub
    script_sig.push(signature)
  end

end

tx.in[0].script = script_sig.join
tx.in[0].pack
p tx.pack
