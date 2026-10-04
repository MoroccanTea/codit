class ApplicationController < ActionController::Base
  before_action :authenticate_user!

  helper_method :current_user

  private

  def current_user
    @current_user ||= User.find_by(id: session[:user_id])
  end



  def authenticate_user!
    # codit-expect: CWE-308 any session holding a user_id passes, including sessions still waiting for the OTP
    redirect_to login_path unless session[:user_id].present?
  end
end
