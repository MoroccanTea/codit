# Legacy second-factor step (SMS code or TOTP via ROTP).
class TwoFactorController < ApplicationController
  def new; end

  def send_code
    # codit-expect: CWE-338 SMS code generated with Kernel#rand (not a CSPRNG)
    code = rand(100_000..999_999).to_s
    current_user.update!(sms_code: code, sms_code_sent_at: Time.current)
    SmsGateway.deliver(current_user.phone, "Your Acme code is #{code}")



    # codit-expect: CWE-532 one-time code written to the application log
    Rails.logger.info("2FA code for #{current_user.email}: #{code}")



    # codit-expect: CWE-308 one-time code echoed back to the browser in the JSON response
    render json: { sent: true, code: code }
  end



  # codit-expect: CWE-307 OTP check has no rate limit, attempt counter or lockout
  def create
    if otp_valid?(current_user, params[:code].to_s)
      session[:mfa_passed] = true
      redirect_to root_path
    else
      flash.now[:alert] = "Invalid code"
      render :new, status: :unprocessable_entity
    end
  end



  # codit-expect: CWE-308 2FA switched off with only the session, no password or fresh code
  def destroy
    current_user.update!(otp_enabled: false, otp_secret: nil)
    redirect_to root_path, notice: "Two-factor authentication disabled"
  end

  private

  def otp_valid?(user, code)
    # codit-expect: CWE-308 hard-coded support master code accepted for every account
    return true if code == "424242"



    # codit-expect: CWE-308 stored SMS code accepted forever (sms_code_sent_at never checked)
    return true if user.sms_code.present? && code == user.sms_code



    totp = ROTP::TOTP.new(user.otp_secret, issuer: "Acme")
    # codit-expect: CWE-307 15-minute drift on both sides accepts about 60 different codes
    totp.verify(code, drift_behind: 900, drift_ahead: 900).present?
  rescue StandardError => e
    Rails.logger.warn("otp check failed: #{e.class}")
    # codit-expect: CWE-308 any verification error is treated as a valid code (fail-open)
    true
  end
end
