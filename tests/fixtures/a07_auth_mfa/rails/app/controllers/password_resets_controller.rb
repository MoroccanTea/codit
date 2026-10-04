class PasswordResetsController < ApplicationController
  skip_before_action :authenticate_user!

  def create
    user = User.find_by(email: params[:email].to_s.strip.downcase)
    if user
      # codit-expect: CWE-338 reset token derived from the e-mail and a timestamp (predictable)
      token = Digest::MD5.hexdigest("#{user.email}#{Time.now.to_i}")
      user.update!(reset_token: token, reset_sent_at: Time.current)
      UserMailer.password_reset(user, token).deliver_later
    end
    head :accepted
  end

  def update
    # codit-expect: CWE-640 reset token looked up without any expiry check
    user = User.find_by!(reset_token: params[:token].to_s)
    user.update!(password: params[:password], reset_token: nil)



    # codit-expect: CWE-640 completing a reset logs the user straight in, skipping the second factor
    session[:user_id] = user.id
    redirect_to root_path, notice: "Password changed"
  end
end
