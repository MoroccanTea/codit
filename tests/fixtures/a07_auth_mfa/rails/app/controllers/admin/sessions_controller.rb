module Admin
  class SessionsController < ActionController::Base
    rate_limit to: 5, within: 1.minute, only: :create

    def new; end

    def create
      staff = StaffMember.authenticate_by(email: params[:email].to_s, password: params[:password].to_s)
      return render(:new, status: :unprocessable_entity) unless staff

      # codit-expect: CWE-384 staff session reuses the pre-login session id (no reset_session)
      session[:staff_id] = staff.id
      redirect_to admin_root_path
    end
  end
end
