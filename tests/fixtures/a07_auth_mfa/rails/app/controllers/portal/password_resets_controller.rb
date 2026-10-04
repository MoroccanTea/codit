module Portal
  class PasswordResetsController < BaseController
    skip_before_action :require_full_session!
    rate_limit to: 5, within: 15.minutes, only: :create

    RESET_TTL = 1.hour

    def create
      user = User.find_by(email: params[:email].to_s.strip.downcase)
      if user
        # codit-safe: CWE-338 token from SecureRandom; only its digest is stored
        token = SecureRandom.urlsafe_base64(32)
        user.update!(reset_digest: Digest::SHA256.hexdigest(token), reset_sent_at: Time.current)
        UserMailer.password_reset(user, token).deliver_later
      end
      head :accepted
    end

    def update
      digest = Digest::SHA256.hexdigest(params[:token].to_s)
      # codit-safe: CWE-640 token only valid for one hour after it was issued
      user = User.where("reset_sent_at > ?", RESET_TTL.ago).find_by!(reset_digest: digest)
      user.update!(password: params[:password], reset_digest: nil, reset_sent_at: nil)
      user.trusted_devices.destroy_all



      # codit-safe: CWE-640 no session is created; the user must sign in again with password and 2FA
      reset_session
      redirect_to "/portal/login", notice: "Password updated, please sign in"
    end
  end
end
