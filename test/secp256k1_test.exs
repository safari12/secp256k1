defmodule Secp256k1Test do
  use ExUnit.Case
  doctest Secp256k1

  @n :binary.decode_unsigned(<<
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
  0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
  0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
  >>)


  describe "generate_key_pair" do
    test "should return a private key less n but greater than 1" do
      key = Secp256k1.generate_key_pair
      |> elem(1)
      |> :binary.decode_unsigned

      assert key > 1 and key < @n
    end

    test "should return tuple of public and private keys" do
      {pub_key, priv_key} = Secp256k1.generate_key_pair
      assert pub_key != nil
      assert priv_key != nil
    end
  end

  describe "generate_public_key" do
    test "should return a valid public from private key" do
      {_, priv_key} = Secp256k1.generate_key_pair
      pub_key = Secp256k1.generate_public_key(priv_key)
      msg = "hello"

      result = priv_key
      |> Secp256k1.sign(msg)
      |> Secp256k1.verify_signature(msg, pub_key)

      assert result == true
    end
  end

  describe "sign" do
    test "should return signature" do
      {_, priv_key} = Secp256k1.generate_key_pair
      sig = Secp256k1.sign(priv_key, "hello")
      assert sig != nil
    end
  end

  describe "verify_signature" do
    test "should return true if signature is valid" do
      msg = "hello"
      {pub_key, priv_key} = Secp256k1.generate_key_pair

      result = priv_key
      |> Secp256k1.sign(msg)
      |> Secp256k1.verify_signature(msg, pub_key)

      assert result == true
    end

    test "should return false if message is invalid" do
      msg = "hello"
      {pub_key, priv_key} = Secp256k1.generate_key_pair

      result = priv_key
      |> Secp256k1.sign("blah")
      |> Secp256k1.verify_signature(msg, pub_key)

      assert result == false
    end

    test "should return false if public key is different" do
      msg = "hello"
      {_, priv_key} = Secp256k1.generate_key_pair
      {pub_key, _} = Secp256k1.generate_key_pair

      result = priv_key
      |> Secp256k1.sign(msg)
      |> Secp256k1.verify_signature(msg, pub_key)

      assert result == false
    end
  end
end
