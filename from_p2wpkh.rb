require 'openssl'
require 'bitcoin'
require 'ffi'
require './tools.rb'
require 'yaml'

include Bitcoin::Util
include Util

str  = ARGF.read()
data = YAML.load(str)

Bitcoin.network = :regtest

signer_wif = 'cPN7UjEySEVfHftqV8PYJeZRsBDRZEEWj4yMrTJwCTTDiDXp8EV8'
signer = Bitcoin::Key.from_base58(signer_wif)
prevout = 1999000000

send_to = 'cTG9tQQhZrjfJYw3TewmVRVhE4kScyNL3fCDL1YXQuGGtghsH1xe'
reciever = Bitcoin::Key.from_base58(send_to)
pubkey_hash = hash160 reciever.addr

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

segwit = Segwit.prepare do |segwit|
  segwit.tx = tx
  segwit.txin = txin
  segwit.txout = txout
  segwit.prevout = prevout
  segwit.p2wpkh_script_code = '4873d013a8b12c1da4d853eb9268b43f9feecf29'
end
sig_hash = double_sha256(segwit.hash_preimage)

script_sig = []

#to p2sh, p2pkh
data['input'].each do |hash|
  sig_obj = Signature.new(signer.priv)
  if !sig_obj.sign(sig_hash).to_hash.bip62.der_check then
    STDERR.puts 'der check failed'
    exit(false)
  end
  signature = int2hex(hex_bytesize(sig_obj.signature)) + sig_obj.signature + int2hex(hex_bytesize(signer.pub)) + signer.pub
  script_sig.push(signature)
end

final_tx = segwit.build do |final_tx|
  final_tx.push '01' + tx.in[0].pack
  final_tx.push '01' + tx.out[0].pack
  final_tx.push '02' + script_sig[0]
end
p final_tx.join
