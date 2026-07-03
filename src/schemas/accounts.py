from pydantic import BaseModel, EmailStr, field_validator

from database import accounts_validators


class EmailSchema(BaseModel):
    email: EmailStr

    @field_validator("email", mode="after")
    @classmethod
    def validate_email(cls, value: EmailStr) -> str:
        return accounts_validators.validate_email(str(value).lower())


class PasswordSchema(BaseModel):
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return accounts_validators.validate_password_strength(value)


class UserRegistrationRequestSchema(EmailSchema, PasswordSchema):
    pass


class UserRegistrationResponseSchema(EmailSchema):
    id: int

    model_config = {
        "from_attributes": True
    }


class UserActivationRequestSchema(EmailSchema):
    token: str


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(EmailSchema):
    pass


class PasswordResetCompleteRequestSchema(EmailSchema, PasswordSchema):
    token: str


class UserLoginRequestSchema(EmailSchema):
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str
