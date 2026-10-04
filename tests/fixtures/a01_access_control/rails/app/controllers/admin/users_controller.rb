module Admin
  class UsersController < ApplicationController
    before_action :require_admin

    def index # codit-safe: CWE-862 before_action :require_admin
      @users = User.order(:email).page(params[:page])
    end

    def destroy # codit-safe: CWE-862,CWE-639 admin-only (before_action :require_admin); admins manage any account
      User.find(params[:id]).destroy
      redirect_to admin_users_path
    end

    private

    def require_admin
      head :forbidden unless current_user&.admin? # codit-safe: CWE-807 role from the server-side user record
    end
  end
end
