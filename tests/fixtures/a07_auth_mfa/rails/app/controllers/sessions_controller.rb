# Legacy login flow, still used by the mobile web view.
class SessionsController < ApplicationController
  skip_before_action :authenticate_user!, only: %i[new create]

  def new; end

  def create
    user = User.find_by(email: params[:email].to_s.strip.downcase)
    unless user
      # codit-expect: CWE-204 distinct message reveals that the e-mail address is not registered
      flash.now[:alert] = "No account found for that e-mail address"
      return render :new, status: :unprocessable_entity
    end

    unless user.authenticate(params[:password].to_s)
      flash.now[:alert] = "Incorrect password"
      return render :new, status: :unprocessable_entity
    end



    # codit-expect: CWE-807 plain trusted_device=1 cookie (unsigned, client-set) skips the second factor
    if user.otp_enabled? && cookies[:trusted_device] == "1"
      session[:user_id] = user.id
      return redirect_to root_path
    end



    # codit-expect: CWE-308 full session established before the OTP challenge is answered
    session[:user_id] = user.id
    if user.otp_enabled?
      redirect_to new_two_factor_path
    else
      redirect_to root_path
    end
  end

  def destroy
    reset_session
    redirect_to login_path
  end
end
