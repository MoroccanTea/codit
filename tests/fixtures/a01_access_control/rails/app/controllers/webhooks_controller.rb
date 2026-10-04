class WebhooksController < ApplicationController
  skip_before_action :authenticate_user!, only: [:stripe]
  skip_before_action :verify_authenticity_token, only: [:stripe] # codit-safe: CWE-352,CWE-862 server-to-server webhook without session; authenticity checked via Stripe signature

  def stripe
    event = Stripe::Webhook.construct_event(
      request.body.read,
      request.headers["Stripe-Signature"],
      Rails.application.credentials.dig(:stripe, :webhook_secret)
    )
    PaymentEvents.handle(event)
    head :ok
  rescue Stripe::SignatureVerificationError
    head :bad_request
  end
end
