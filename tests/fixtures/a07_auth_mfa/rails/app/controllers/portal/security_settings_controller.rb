module Portal
  class SecuritySettingsController < BaseController
    def show; end



    # codit-safe: CWE-308 disabling 2FA requires the current password and a fresh TOTP code
    def disable_two_factor
      password_ok = current_user.authenticate(params[:current_password].to_s)
      code_ok = ROTP::TOTP.new(current_user.otp_secret).verify(params[:code].to_s, drift_behind: 30).present?
      unless password_ok && code_ok
        return redirect_to security_settings_path, alert: "Please confirm your password and a current code"
      end

      current_user.update!(otp_enabled: false, otp_secret: nil)
      current_user.trusted_devices.destroy_all
      SecurityMailer.two_factor_disabled(current_user).deliver_later
      redirect_to security_settings_path, notice: "Two-factor authentication disabled"
    end
  end
end
