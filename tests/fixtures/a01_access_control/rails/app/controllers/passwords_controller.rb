class PasswordsController < ApplicationController
  skip_before_action :authenticate_user!, only: [:new, :create, :edit, :update] # codit-safe: CWE-862 password-reset flow is anonymous by design; update requires the signed reset token

  def new; end

  def create
    user = User.find_by(email: params[:email])
    PasswordMailer.with(user: user).reset.deliver_later if user
    redirect_to new_session_path, notice: "If the address exists, a reset link was sent."
  end

  def edit
    @user = User.find_by_token_for!(:password_reset, params[:token])
  end

  def update
    @user = User.find_by_token_for!(:password_reset, params[:token])
    if @user.update(params.permit(:password, :password_confirmation))
      redirect_to new_session_path, notice: "Password updated."
    else
      render :edit, status: :unprocessable_entity
    end
  end
end
