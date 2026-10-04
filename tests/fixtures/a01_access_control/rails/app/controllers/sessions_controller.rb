class SessionsController < ApplicationController
  skip_before_action :authenticate_user!, only: [:new, :create] # codit-safe: CWE-862 login form and login POST must be reachable anonymously

  def new; end

  def create
    user = User.authenticate_by(email: params[:email], password: params[:password])
    return render(:new, status: :unprocessable_entity) unless user

    reset_session
    session[:user_id] = user.id
    redirect_to params[:return_to] # codit-expect: CWE-601 post-login redirect to an arbitrary return_to parameter
  end

  def sso_return
    target = url_from(params[:return_to]) || root_path
    redirect_to target # codit-safe: CWE-601 url_from only accepts same-host URLs
  end
end
