defmodule Secp256k1 do
  @moduledoc """
  Generates keys and signs messages based on secure constants for
  elliptic curve
  """

  @doc """
  Generates a key pair tuple, first element being the public key and
  last element being the private key
  """
  @spec generate_key_pair() :: binary
  def generate_key_pair do
    :crypto.generate_key(:ecdh, :secp256k1)
  end

  @doc """
  Signs a message with private key
  """
  @spec sign(binary, binary) :: binary
  def sign(private_key, msg) do
    :crypto.sign(:ecdsa, :sha256, msg, [private_key, :secp256k1])
  end

  @doc """
  Verifies a given signature with public key and message
  """
  @spec verify_signature(binary, binary, binary) :: boolean
  def verify_signature(signature, msg, public_key) do
    :crypto.verify(:ecdsa, :sha256, msg, signature, [public_key, :secp256k1])
  end
end
