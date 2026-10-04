module Portal
  class SessionsController < BaseController
    skip_before_action :require_full_session!, only: %i[new create]
    rate_limit to: 10, within: 3.minutes, only: :create

    def new; end

    def create
      user = User.authenticate_by(email: params[:email].to_s.strip.downcase, password: params[:password].to_s)
      unless user
        # codit-safe: CWE-204 one generic message whether or not the e-mail exists
        flash.now[:alert] = "Invalid e-mail or password"
        return render :new, status: :unprocessable_entity
      end

      reset_session
      device_token = cookies.encrypted[:trusted_device]
      Rails.logger.info("password step ok for user #{user.id}")

      # codit-safe: CWE-807 remember-device token is encrypted and matched against a server-side record
      if user.otp_enabled? && TrustedDevice.active_for?(user, device_token)
        start_full_session(user)
        return redirect_to root_path
      end

      unless user.otp_enabled?
        start_full_session(user)
        return redirect_to root_path
      end



      # codit-safe: CWE-308 only a pending marker is stored until the OTP has been verified
      session[:pending_user_id] = user.id
      session[:pending_since] = Time.current.to_i
      redirect_to new_two_factor_challenge_path
    end

    private

    def start_full_session(user)
      reset_session
      # codit-safe: CWE-384 session id rotated immediately before the user id is stored
      session[:user_id] = user.id
      session[:mfa_verified_at] = Time.current.to_i
    end
  end
end
