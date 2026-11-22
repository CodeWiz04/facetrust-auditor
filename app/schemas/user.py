"""Response schemas for users and roles."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict

from app.models.user import UserRole


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    role: UserRole
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None = None


class UserListResponse(BaseModel):
    items: list[UserResponse]
    total: int


class RoleUpdateRequest(BaseModel):
    role: UserRole
