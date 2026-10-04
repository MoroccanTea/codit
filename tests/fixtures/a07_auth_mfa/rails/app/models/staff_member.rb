class StaffMember < ApplicationRecord
  has_secure_password

  validates :email, presence: true, uniqueness: true



  # codit-safe: CWE-521 staff passwords need 14+ characters and are checked against the breach list
  validates :password, length: { minimum: 14, maximum: 128 }, not_pwned: true, allow_nil: true



  def display_name
    "#{first_name} #{last_name}".strip
  end
end
