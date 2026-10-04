module Portal
  # Second-factor step of the current login flow. Reached with a pending session only.
  class TwoFactorChallengesController < BaseController
    skip_before_action :require_full_session!
    before_action :load_pending_user
    rate_limit to: 5, within: 5.minutes, only: :create,
               with: -> { redirect_to "/portal/login", alert: "Too many attempts" }

    MAX_FAILED_ATTEMPTS = 5

    def new; end

    def send_code
      # codit-safe: CWE-338 SMS code drawn from SecureRandom
      code = format("%06d", SecureRandom.random_number(1_000_000))
      @user.update!(sms_code_digest: BCrypt::Password.create(code), sms_code_sent_at: Time.current, otp_failed_attempts: 0)
      SmsGateway.deliver(@user.phone, "Your Acme code is #{code}")



      # codit-safe: CWE-532 only the user id is logged, never the code
      Rails.logger.info("2FA code sent to user #{@user.id}")



      # codit-safe: CWE-308 response never contains the code
      render json: { sent: true }
    end



    # codit-safe: CWE-307 rate_limit plus a per-user failed-attempt counter with lockout
    def create
      if @user.otp_failed_attempts >= MAX_FAILED_ATTEMPTS
        reset_session
        return redirect_to "/portal/login", alert: "Too many attempts"
      end

      if otp_valid?(@user, params[:code].to_s)
        reset_session
        session[:user_id] = @user.id
        session[:mfa_verified_at] = Time.current.to_i
        @user.update!(otp_failed_attempts: 0, sms_code_digest: nil)
        redirect_to root_path
      else
        @user.increment!(:otp_failed_attempts)
        render :new, status: :unprocessable_entity
      end
    end

    private

    def load_pending_user
      @user = User.find_by(id: session[:pending_user_id])
      redirect_to "/portal/login" if @user.nil? || session[:pending_since].to_i < 10.minutes.ago.to_i
    end

    def otp_valid?(user, code)
      # codit-safe: CWE-308 stored SMS code honoured only within 5 minutes of being sent
      if user.sms_code_digest.present? && user.sms_code_sent_at > 5.minutes.ago
        return BCrypt::Password.new(user.sms_code_digest).is_password?(code)
      end



      totp = ROTP::TOTP.new(user.otp_secret, issuer: "Acme")
      # codit-safe: CWE-307 drift limited to one 30-second step
      totp.verify(code, drift_behind: 30, drift_ahead: 0, after: user.otp_last_used_at).present?
    rescue ROTP::Error, ArgumentError
      # codit-safe: CWE-308 fail closed when verification raises
      false
    end
  end
end
