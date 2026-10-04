module Portal
  class BaseController < ActionController::Base
    before_action :require_full_session!

    helper_method :current_user

    private

    def current_user
      @current_user ||= User.find_by(id: session[:user_id])
    end



    def require_full_session!
      # codit-safe: CWE-308 a pending-2FA session (pending_user_id only) never satisfies this guard
      return if session[:user_id].present? && session[:mfa_verified_at].present?

      redirect_to(session[:pending_user_id] ? new_two_factor_challenge_path : "/portal/login")
    end
  end
end
