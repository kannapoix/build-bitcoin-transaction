require 'test/unit'
require './tools.rb'
include Util

class UtilTest < Test::Unit::TestCase
  def test_to_little
    assert_equal "00ff", to_little("ff00")
  end

  def test_hex_bytesize
    assert_equal 2, hex_bytesize("ffff")
    assert_equal 25, hex_bytesize("76a914b7cdeeea1f8253e2fd709f2cfe7f05b71afa752a88ac")
    assert_equal 0, hex_bytesize("")
  end

  def test_int2hex
    assert_equal "f", int2hex(15)
  end

  def test_to_var_int
    int = 1
    int2 = 25
    assert_equal "01", to_var_int(int)
    assert_equal "19", to_var_int(int2)
  end

  def test_SHA256
  end
end

class TxTest < Test::Unit::TestCase
  def test_version
    tx = Tx.new
    tx.version=1
    assert_equal "01000000", tx.version
  end

  def test_hash_code
    tx = Tx.new
    tx.hash_code=1
    assert_equal "01000000", tx.hash_code
  end
end

class TxinTest < Test::Unit::TestCase
  def test_prev_output_index
    input = Txin.new
    input.prev_output_index=1
    assert_equal "01000000", input.prev_output_index
  end
end
class TxoutTest < Test::Unit::TestCase
  def test_consume
    output = Txout.new
    output.consume = 5000000000
    assert_equal "00f2052a01000000", output.consume
  end
end
