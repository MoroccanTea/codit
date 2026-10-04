Rails.application.routes.draw do
  resource :session, only: [:new, :create]
  get "sso/return", to: "sessions#sso_return"
  resources :passwords, only: [:new, :create, :edit, :update], param: :token
  resources :projects
  resource :profile, controller: "users", only: [:update] do
    get :beta_features
    patch :preferences
  end
  post "webhooks/stripe", to: "webhooks#stripe"

  namespace :admin do
    resources :users, only: [:index, :destroy]
  end
end
