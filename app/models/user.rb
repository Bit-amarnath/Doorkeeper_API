class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable, :trackable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :validatable

  validates :email, format: URI::MailTo::EMAIL_REGEXP
  enum role: [:user, :admin]

  # the authentication method from devise documentation
  def self.authenticate(email, password)
    user = User.find_for_authentication(email: email)

    # if user && user.valid_password?

    # instead of writing the above one , we can do the below one
    user&.valid_password?(password) ? user : nil
  end
end
