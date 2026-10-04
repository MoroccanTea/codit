class UsersController < ApplicationController
  def update
    # codit-expect: CWE-915 permit! binds every attribute, including otp_enabled and admin
    if current_user.update(params.require(:user).permit!)
      redirect_to root_path, notice: "Profile updated"
    else
      render :edit, status: :unprocessable_entity
    end
  end



  def update_preferences
    # codit-safe: CWE-915 explicit allow-list of harmless profile fields
    if current_user.update(params.require(:user).permit(:name, :locale, :time_zone))
      redirect_to root_path, notice: "Preferences saved"
    else
      render :edit, status: :unprocessable_entity
    end
  end
end
