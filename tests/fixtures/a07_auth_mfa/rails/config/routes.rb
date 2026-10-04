Rails.application.routes.draw do
  root "dashboard#show"

  # Legacy flow (pre-2024 UI, still enabled for the mobile web view)
  get    "/login",                to: "sessions#new",           as: :login
  post   "/login",                to: "sessions#create"
  get    "/two_factor",           to: "two_factor#new",         as: :new_two_factor
  post   "/two_factor/send_code", to: "two_factor#send_code"
  post   "/two_factor",           to: "two_factor#create"
  delete "/two_factor",           to: "two_factor#destroy"
  patch  "/profile",              to: "users#update"
  patch  "/profile/preferences",  to: "users#update_preferences"
  post   "/password_resets",      to: "password_resets#create"
  patch  "/password_resets",      to: "password_resets#update"

  namespace :admin do
    post "/login", to: "sessions#create"
    root "dashboard#show"
  end

  # Current flow
  scope module: :portal, path: "/portal" do
    post   "/login",                         to: "sessions#create"
    get    "/two_factor_challenge",          to: "two_factor_challenges#new", as: :new_two_factor_challenge
    post   "/two_factor_challenge/send_code", to: "two_factor_challenges#send_code"
    post   "/two_factor_challenge",          to: "two_factor_challenges#create"
    delete "/security/two_factor",           to: "security_settings#disable_two_factor"
    get    "/security",                      to: "security_settings#show", as: :security_settings
    post   "/password_resets",               to: "password_resets#create"
    patch  "/password_resets",               to: "password_resets#update"
  end
end
