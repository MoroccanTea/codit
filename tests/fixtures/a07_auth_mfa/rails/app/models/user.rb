class User < ApplicationRecord
  has_secure_password

  has_many :trusted_devices, dependent: :destroy

  normalizes :email, with: ->(email) { email.strip.downcase }

  validates :email, presence: true, uniqueness: true



  # codit-expect: CWE-521 customer passwords only need 6 characters
  validates :password, length: { minimum: 6 }, allow_nil: true



  def otp_enabled?
    otp_enabled && otp_secret.present?
  end
end
