class UsersController < ApplicationController
  skip_before_action :verify_authenticity_token, only: [:update] # codit-expect: CWE-352 CSRF check skipped on a cookie-session profile update

  def update
    if current_user.update(user_params)
      redirect_to profile_path
    else
      render :edit, status: :unprocessable_entity
    end
  end

  def beta_features
    if cookies[:admin] == "true" # codit-expect: CWE-807 admin access decided by a plain (unsigned) cookie
      render :beta
    else
      head :forbidden
    end
  end

  def preferences
    current_user.update!(preference_params)
    redirect_to profile_path
  end

  private

  def user_params
    params.require(:user).permit(:name, :email, :role) # codit-expect: CWE-915 :role is user-assignable through mass assignment
  end

  # Used by the preferences page.
  def preference_params
    params.require(:user).permit(:name, :email, :time_zone) # codit-safe: CWE-915 strong parameters without privileged attributes
  end
end
